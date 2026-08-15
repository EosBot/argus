"""ToolSelection — LLM-powered intelligent tool selection.

Given a task description, selects the best tool(s) from the ToolRegistry
using LLM-based reasoning with rule-based fallback when LLM is unavailable.

Usage::

    from backend.tools.selection import ToolSelection

    selector = ToolSelection()
    result = await selector.select("Scan example.com for open ports")
    print(result.selected_tools)  # ["nmap_scanner"]
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from backend.tools.registry import ToolRegistry, get_tool_registry

logger = logging.getLogger(__name__)


@dataclass
class SelectionResult:
    """Result of tool selection.

    Attributes:
        task: Original task description.
        selected_tools: List of selected tool names.
        confidence: Selection confidence 0.0-1.0.
        reasoning: Human-readable reasoning for the selection.
        method: Selection method used ("llm" or "rule_based").
        alternatives: Alternative tools that could also work.
    """

    task: str
    selected_tools: list[str] = field(default_factory=list)
    confidence: float = 0.0
    reasoning: str = ""
    method: str = "rule_based"
    alternatives: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "selected_tools": self.selected_tools,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "method": self.method,
            "alternatives": self.alternatives,
        }


class ToolSelection:
    """Intelligent tool selection based on task description.

    Uses LLM to analyze task requirements and select optimal tools.
    Falls back to rule-based keyword matching when LLM is unavailable.
    """

    # Keyword-to-capability mapping for rule-based selection
    KEYWORD_MAP: dict[str, list[str]] = {
        # Network scanning
        "scan": ["port_scan", "scanning", "vulnerability"],
        "port": ["port_scan", "network"],
        "nmap": ["port_scan", "network"],
        "nuclei": ["vulnerability", "scanning"],
        "vulnerability": ["vulnerability", "scanning"],
        "exploit": ["vulnerability", "exploitation"],
        # Domain/DNS
        "domain": ["dns", "domain", "subdomain"],
        "subdomain": ["subdomain", "enumeration"],
        "dns": ["dns", "resolution"],
        "whois": ["whois", "domain"],
        # Dark web
        "onion": ["onion", "dark_web"],
        "tor": ["tor", "dark_web"],
        "dark web": ["dark_web"],
        "marketplace": ["marketplace", "dark_web"],
        # Crypto
        "bitcoin": ["btc", "blockchain"],
        "btc": ["btc", "blockchain"],
        "ethereum": ["eth", "blockchain"],
        "eth": ["eth", "blockchain"],
        "wallet": ["wallet", "blockchain"],
        "crypto": ["blockchain"],
        "transaction": ["tracing", "blockchain"],
        # People
        "username": ["username", "search"],
        "email": ["email", "lookup"],
        "phone": ["phone", "lookup"],
        "person": ["people", "search"],
        "social": ["social_media", "profile"],
        # IOC / Forensic
        "ioc": ["ioc", "extraction"],
        "hash": ["hash", "file"],
        "ip": ["ip", "geolocation"],
        "geolocate": ["geolocation", "ip"],
        "forensic": ["forensics", "analysis"],
        # Threat Intel
        "threat": ["threat_intel", "analysis"],
        "attribution": ["attribution", "actor"],
        "virustotal": ["virustotal", "reputation"],
        "malware": ["malware", "analysis"],
        "yara": ["yara", "rules"],
        # OSINT
        "osint": ["osint", "search"],
        "search": ["search"],
        "google": ["google", "search"],
        "github": ["github", "secrets"],
        # Infrastructure
        "ssl": ["ssl", "tls"],
        "certificate": ["certificate", "ssl"],
        "technology": ["technology", "detection"],
        "shodan": ["shodan", "search"],
        "censys": ["censys", "search"],
        # Report
        "report": ["report", "generation"],
        "timeline": ["timeline", "events"],
        "graph": ["graph", "visualization"],
        "export": ["export"],
    }

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        llm_client: Any = None,
    ) -> None:
        """Initialize tool selector.

        Args:
            registry: ToolRegistry instance (uses global default if None).
            llm_client: Optional LLM client with async complete(prompt) method.
        """
        self._registry = registry or get_tool_registry()
        self._llm = llm_client

    async def select(
        self,
        task: str,
        max_tools: int = 3,
        min_confidence: float = 0.3,
    ) -> SelectionResult:
        """Select the best tool(s) for a task.

        Args:
            task: Task description string.
            max_tools: Maximum number of tools to select.
            min_confidence: Minimum confidence threshold.

        Returns:
            SelectionResult with selected tools and metadata.
        """
        if not task or not task.strip():
            return SelectionResult(
                task=task,
                reasoning="Empty task description",
                confidence=0.0,
            )

        # Try LLM-based selection first
        if self._llm is not None:
            try:
                result = await self._select_with_llm(task, max_tools)
                if result.confidence >= min_confidence:
                    return result
            except Exception as exc:
                logger.debug("LLM selection failed, falling back to rules: %s", exc)

        # Rule-based fallback
        return self._select_with_rules(task, max_tools)

    async def _select_with_llm(
        self, task: str, max_tools: int
    ) -> SelectionResult:
        """Use LLM to select tools based on task description."""
        available_tools = self._registry.list_tools()
        tool_summaries = [
            f"- {t['name']}: {t['description']} (caps: {', '.join(t['capabilities'][:4])})"
            for t in available_tools
        ]

        prompt = f"""Given the following investigation task, select the best tool(s) from the available tools.

Task: {task}

Available tools (showing up to 30):
{chr(10).join(tool_summaries[:30])}

Select up to {max_tools} tools that best match this task. Respond in JSON format:
{{"tools": ["tool_name_1", "tool_name_2"], "confidence": 0.9, "reasoning": "brief explanation"}}

JSON response:"""

        try:
            response = await self._llm.complete(prompt)
            # Try to extract JSON from response
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                tool_names = data.get("tools", [])[:max_tools]
                # Validate tools exist
                valid_tools = [
                    t for t in tool_names if t in self._registry
                ]
                if valid_tools:
                    # Find alternatives
                    all_caps = set()
                    for t in valid_tools:
                        meta = self._registry.get(t)
                        if meta:
                            all_caps.update(meta.capabilities)
                    alternatives = [
                        t.name for t in self._registry.search(task)
                        if t.name not in valid_tools
                    ][:3]

                    return SelectionResult(
                        task=task,
                        selected_tools=valid_tools,
                        confidence=float(data.get("confidence", 0.7)),
                        reasoning=data.get("reasoning", "LLM selection"),
                        method="llm",
                        alternatives=alternatives,
                    )
        except (json.JSONDecodeError, AttributeError, TypeError) as exc:
            logger.debug("LLM response parsing failed: %s", exc)

        # If LLM parsing failed, fall back to rules
        return self._select_with_rules(task, max_tools)

    def _select_with_rules(self, task: str, max_tools: int) -> SelectionResult:
        """Rule-based tool selection using keyword matching."""
        task_lower = task.lower()
        scored_tools: dict[str, float] = {}

        # Score each tool based on keyword matches
        for tool in self._registry.list_tools():
            score = 0.0
            tool_name = tool["name"].lower()
            tool_desc = tool["description"].lower()
            tool_caps = [c.lower() for c in tool["capabilities"]]

            for keyword, related_caps in self.KEYWORD_MAP.items():
                if keyword in task_lower:
                    # Direct keyword match in name/description
                    if keyword in tool_name or keyword in tool_desc:
                        score += 2.0
                    # Capability match
                    for cap in related_caps:
                        if cap.lower() in tool_caps:
                            score += 1.5

            # Bonus for reliability
            score += tool.get("reliability_score", 0.5) * 0.5

            if score > 0:
                scored_tools[tool["name"]] = score

        # Sort by score descending
        sorted_tools = sorted(
            scored_tools.items(), key=lambda x: x[1], reverse=True
        )

        selected = [name for name, _ in sorted_tools[:max_tools]]
        alternatives = [name for name, _ in sorted_tools[max_tools:max_tools + 3]]

        # Calculate confidence based on score spread
        confidence = 0.0
        if sorted_tools:
            top_score = sorted_tools[0][1]
            if len(sorted_tools) > 1:
                second_score = sorted_tools[1][1]
                # Higher gap = higher confidence
                confidence = min(0.95, 0.5 + (top_score - second_score) / top_score * 0.5)
            else:
                confidence = 0.6

        reasoning = (
            f"Rule-based selection: matched {len(scored_tools)} tools "
            f"for task keywords in '{task[:50]}...'"
        )

        return SelectionResult(
            task=task,
            selected_tools=selected,
            confidence=round(confidence, 2),
            reasoning=reasoning,
            method="rule_based",
            alternatives=alternatives,
        )
