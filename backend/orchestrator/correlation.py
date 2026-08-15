"""Correlation engine — cross-agent finding correlation.

Cross-references findings from different agents to identify:
- Same IOC found by multiple agents (confidence boost)
- Related entities (shared infrastructure, common attribution)
- Temporal patterns across agent results
- Contradictions between agent findings
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from backend.core.neo4j_client import neo4j_client

logger = logging.getLogger(__name__)


@dataclass
class CorrelationFinding:
    """A correlation discovered between agent findings.

    Attributes:
        correlation_type: Type of correlation (shared_ioc, related_entity, temporal_pattern, contradiction).
        source_agents: List of agent names involved.
        description: Human-readable description of the correlation.
        confidence: Confidence score (0.0 - 1.0).
        entities: Related entities (IOCs, IPs, domains, etc.).
        evidence: Supporting evidence dict.
    """

    correlation_type: str
    source_agents: list[str]
    description: str
    confidence: float = 0.5
    entities: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_type": self.correlation_type,
            "source_agents": self.source_agents,
            "description": self.description,
            "confidence": self.confidence,
            "entities": self.entities,
            "evidence": self.evidence,
        }


@dataclass
class CorrelationReport:
    """Complete correlation report for an investigation.

    Attributes:
        investigation_id: Investigation identifier.
        correlations: List of discovered correlations.
        summary: Human-readable summary.
        risk_score: Aggregated risk score (0-100).
    """

    investigation_id: str
    correlations: list[CorrelationFinding] = field(default_factory=list)
    summary: str = ""
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "correlations": [c.to_dict() for c in self.correlations],
            "summary": self.summary,
            "risk_score": self.risk_score,
        }


class CorrelationEngine:
    """Cross-references findings from different agents.

    Uses Neo4j for graph-based correlation and in-memory analysis
    for pattern matching. Identifies shared IOCs, infrastructure
    overlaps, and attribution links.

    Usage::

        engine = CorrelationEngine()
        report = await engine.correlate_all(agent_results)
        for finding in report.correlations:
            print(finding.description)
    """

    async def correlate_all(
        self,
        investigation_id: str,
        agent_results: dict[str, dict[str, Any]],
    ) -> CorrelationReport:
        """Run full correlation analysis on all agent results.

        Args:
            investigation_id: Investigation identifier.
            agent_results: Dict mapping agent_name → result dict.

        Returns:
            CorrelationReport with all discovered correlations.
        """
        correlations: list[CorrelationFinding] = []

        # Correlate IOCs across agents
        ioc_correlations = self._correlate_iocs(agent_results)
        correlations.extend(ioc_correlations)

        # Correlate infrastructure (shared IPs, ASNs, countries)
        infra_correlations = self._correlate_infrastructure(agent_results)
        correlations.extend(infra_correlations)

        # Correlate entities (domains, emails, wallets)
        entity_correlations = self._correlate_entities(agent_results)
        correlations.extend(entity_correlations)

        # Check for contradictions
        contradictions = self._detect_contradictions(agent_results)
        correlations.extend(contradictions)

        # Store correlations in Neo4j
        await self._store_correlations(investigation_id, correlations)

        # Calculate risk score
        risk_score = self._calculate_risk_score(correlations)

        # Build summary
        summary = self._build_summary(correlations, risk_score)

        return CorrelationReport(
            investigation_id=investigation_id,
            correlations=correlations,
            summary=summary,
            risk_score=risk_score,
        )

    def _correlate_iocs(
        self,
        agent_results: dict[str, dict[str, Any]],
    ) -> list[CorrelationFinding]:
        """Find IOCs mentioned by multiple agents."""
        correlations: list[CorrelationFinding] = []

        # Collect IOCs per agent
        agent_iocs: dict[str, dict[str, list[str]]] = {}
        for agent_name, result in agent_results.items():
            iocs = result.get("iocs", {})
            if isinstance(iocs, dict):
                agent_iocs[agent_name] = iocs

        # Find shared IOCs across agents
        all_ioc_types: set[str] = set()
        for iocs in agent_iocs.values():
            all_ioc_types.update(iocs.keys())

        for ioc_type in all_ioc_types:
            ioc_agents: dict[str, list[str]] = {}
            for agent_name, iocs in agent_iocs.items():
                values = iocs.get(ioc_type, [])
                if values:
                    for v in values:
                        ioc_agents.setdefault(v, []).append(agent_name)

            # IOCs found by multiple agents
            for ioc_value, ioc_agent_list in ioc_agents.items():
                if len(ioc_agent_list) > 1:
                    confidence = min(0.5 + (len(ioc_agent_list) * 0.15), 1.0)
                    agent_str = ", ".join(ioc_agent_list)
                    correlations.append(
                        CorrelationFinding(
                            correlation_type="shared_ioc",
                            source_agents=ioc_agent_list,
                            description=(
                                f"IOC '{ioc_value}' ({ioc_type}) found by "
                                f"{len(ioc_agent_list)} agents: {agent_str}"
                            ),
                            confidence=confidence,
                            entities=[ioc_value],
                            evidence={"ioc_type": ioc_type, "agents": ioc_agent_list},
                        )
                    )

        return correlations

    def _correlate_infrastructure(
        self,
        agent_results: dict[str, dict[str, Any]],
    ) -> list[CorrelationFinding]:
        """Find shared infrastructure across agent results."""
        correlations: list[CorrelationFinding] = []

        # Collect geolocation data per agent
        agent_geo: dict[str, list[dict]] = {}
        for agent_name, result in agent_results.items():
            geo = result.get("geolocation", [])
            if isinstance(geo, list) and geo:
                agent_geo[agent_name] = geo

        if len(agent_geo) < 2:
            return correlations

        # Find shared countries, ASNs, orgs
        agent_countries: dict[str, set[str]] = {}
        agent_asns: dict[str, set[str]] = {}
        agent_orgs: dict[str, set[str]] = {}

        for agent_name, geo_list in agent_geo.items():
            for geo in geo_list:
                if isinstance(geo, dict):
                    country = geo.get("country")
                    asn = geo.get("asn")
                    org = geo.get("org")
                    if country:
                        agent_countries.setdefault(agent_name, set()).add(country)
                    if asn:
                        agent_asns.setdefault(agent_name, set()).add(str(asn))
                    if org:
                        agent_orgs.setdefault(agent_name, set()).add(org)

        # Find shared countries
        all_countries: dict[str, list[str]] = {}
        for agent_name, countries in agent_countries.items():
            for country in countries:
                all_countries.setdefault(country, []).append(agent_name)

        for country, agents in all_countries.items():
            if len(agents) > 1:
                correlations.append(
                    CorrelationFinding(
                        correlation_type="shared_infrastructure",
                        source_agents=agents,
                        description=f"Shared infrastructure in {country} across agents: {', '.join(agents)}",
                        confidence=0.7,
                        entities=[country],
                        evidence={"country": country, "agents": agents},
                    )
                )

        return correlations

    def _correlate_entities(
        self,
        agent_results: dict[str, dict[str, Any]],
    ) -> list[CorrelationFinding]:
        """Find related entities (domains, emails, wallets) across agents."""
        correlations: list[CorrelationFinding] = []

        # Collect entities per agent
        agent_entities: dict[str, set[str]] = {}
        for agent_name, result in agent_results.items():
            entities = result.get("entities", [])
            if isinstance(entities, list):
                agent_entities[agent_name] = {str(e) for e in entities}

        if len(agent_entities) < 2:
            return correlations

        # Find shared entities
        all_entities: dict[str, list[str]] = {}
        for agent_name, entities in agent_entities.items():
            for entity in entities:
                all_entities.setdefault(entity, []).append(agent_name)

        for entity, agents in all_entities.items():
            if len(agents) > 1:
                correlations.append(
                    CorrelationFinding(
                        correlation_type="related_entity",
                        source_agents=agents,
                        description=f"Entity '{entity}' found by multiple agents: {', '.join(agents)}",
                        confidence=0.8,
                        entities=[entity],
                        evidence={"entity": entity, "agents": agents},
                    )
                )

        return correlations

    def _detect_contradictions(
        self,
        agent_results: dict[str, dict[str, Any]],
    ) -> list[CorrelationFinding]:
        """Detect contradictions between agent findings."""
        correlations: list[CorrelationFinding] = []

        # Check for conflicting attribution
        attributions: dict[str, str] = {}
        for agent_name, result in agent_results.items():
            attr = result.get("attribution", {})
            if isinstance(attr, dict) and attr.get("verdict"):
                attributions[agent_name] = attr["verdict"]

        if len(attributions) > 1:
            unique_verdicts = set(attributions.values())
            if len(unique_verdicts) > 1:
                agents = list(attributions.keys())
                correlations.append(
                    CorrelationFinding(
                        correlation_type="contradiction",
                        source_agents=agents,
                        description=(
                            f"Conflicting attribution verdicts: "
                            + "; ".join(f"{a}: {v}" for a, v in attributions.items())
                        ),
                        confidence=0.6,
                        evidence={"attributions": attributions},
                    )
                )

        return correlations

    async def _store_correlations(
        self,
        investigation_id: str,
        correlations: list[CorrelationFinding],
    ) -> None:
        """Store correlation findings in Neo4j graph."""
        if not neo4j_client.is_connected:
            return

        try:
            # Create investigation node if not exists
            await neo4j_client.run_query(
                "MERGE (i:Investigation {id: $id})",
                {"id": investigation_id},
            )

            # Create correlation nodes
            for corr in correlations:
                await neo4j_client.run_query(
                    """
                    MATCH (i:Investigation {id: $inv_id})
                    MERGE (c:Correlation {type: $type, description: $desc})
                    SET c.confidence = $confidence, c.agents = $agents
                    MERGE (i)-[:HAS_CORRELATION]->(c)
                    """,
                    {
                        "inv_id": investigation_id,
                        "type": corr.correlation_type,
                        "desc": corr.description,
                        "confidence": corr.confidence,
                        "agents": corr.source_agents,
                    },
                )

                # Create entity nodes
                for entity in corr.entities:
                    await neo4j_client.merge_entity(
                        "correlation_entity",
                        entity,
                        {"investigation_id": investigation_id},
                    )

        except Exception as exc:
            logger.warning("Failed to store correlations in Neo4j: %s", exc)

    def _calculate_risk_score(self, correlations: list[CorrelationFinding]) -> float:
        """Calculate aggregated risk score from correlations.

        Score is based on:
        - Number of shared IOCs (more = higher risk)
        - Confidence of correlations
        - Presence of contradictions (reduces confidence)
        """
        if not correlations:
            return 0.0

        score = 0.0
        for corr in correlations:
            if corr.correlation_type == "shared_ioc":
                score += 15.0 * corr.confidence
            elif corr.correlation_type == "shared_infrastructure":
                score += 10.0 * corr.confidence
            elif corr.correlation_type == "related_entity":
                score += 12.0 * corr.confidence
            elif corr.correlation_type == "contradiction":
                score += 5.0  # Contradictions add uncertainty

        return min(score, 100.0)

    def _build_summary(
        self,
        correlations: list[CorrelationFinding],
        risk_score: float,
    ) -> str:
        """Build human-readable summary of correlations."""
        if not correlations:
            return "No significant correlations found between agent findings."

        parts = [f"Found {len(correlations)} correlations. Risk score: {risk_score:.0f}/100."]

        by_type: dict[str, int] = {}
        for c in correlations:
            by_type[c.correlation_type] = by_type.get(c.correlation_type, 0) + 1

        for corr_type, count in sorted(by_type.items()):
            parts.append(f"  - {corr_type}: {count}")

        return "\n".join(parts)
