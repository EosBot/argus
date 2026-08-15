"""Investigation Orchestrator for ARGUS.

Coordinates all intelligence modules (IOC extraction, geolocation, link
analysis, temporal analysis, attribution, frameworks, crypto tracing)
into a single pipeline that produces a consolidated investigation report.

Usage::

    orchestrator = InvestigationOrchestrator()
    result = orchestrator.run_full_pipeline("Check http://evil.com and 1.2.3.4")
    report = orchestrator.generate_report()
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from argus_engine.intel.ioc_extractor import IOCExtractor
from argus_engine.intel.geolocate import GeoLocator
from argus_engine.intel.link_analysis import LinkAnalyzer
from argus_engine.intel.temporal import TemporalAnalyzer
from argus_engine.intel.attribution import AttributionEngine
from argus_engine.intel.frameworks import FrameworkAnalyzer
from argus_engine.intel.crypto_tracer import CryptoTracer

_logger = logging.getLogger(__name__)


class InvestigationOrchestrator:
    """Orchestrates all intelligence modules into a unified investigation pipeline.

    Pipeline stages:
        1. Extract — IOC extraction from raw text
        2. Geolocate — IP geolocation and subdomain discovery
        3. Relate — Entity relationship graph analysis
        4. Temporize — Timeline construction and anomaly detection
        5. Attribute — Multi-factor actor attribution
        6. Framework — MITRE ATT&CK, Diamond Model, Kill Chain mapping
        7. Crypto — Cryptocurrency wallet tracing
        8. Report — Consolidated Markdown report generation
    """

    def __init__(self, investigation_id: str | None = None) -> None:
        """Initialize the investigation orchestrator.

        Args:
            investigation_id: Optional unique identifier for this investigation.
                Auto-generated UUID if not provided.
        """
        self.investigation_id = investigation_id or str(uuid.uuid4())
        self.created_at = datetime.now(timezone.utc)
        self.metadata: dict[str, Any] = {}

        # Intelligence modules
        self._extractor = IOCExtractor()
        self._geo = GeoLocator()
        self._link = LinkAnalyzer()
        self._temporal = TemporalAnalyzer()
        self._attribution = AttributionEngine()
        self._frameworks = FrameworkAnalyzer()
        self._crypto = CryptoTracer()

        # Findings accumulator
        self._findings: dict[str, Any] = {
            "iocs": {},
            "geolocation": [],
            "links": {},
            "temporal": {},
            "attribution": {},
            "frameworks": {},
            "crypto": {},
        }

        self._pipeline_log: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Full pipeline
    # ------------------------------------------------------------------

    def run_full_pipeline(self, text: str, metadata: dict | None = None) -> dict[str, Any]:
        """Execute the complete investigation pipeline.

        Runs all intelligence modules sequentially. If a module fails,
        the error is logged and the pipeline continues with the next stage.

        Args:
            text: Raw text to investigate (report, threat intel, etc.).
            metadata: Optional metadata dict (source, TLP, analyst, etc.).

        Returns:
            Consolidated findings dict from all pipeline stages.
        """
        self.metadata = metadata or {}
        self._pipeline_log.append({
            "event": "pipeline_start",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "text_length": len(text),
        })

        # Stage 1: Extract IOCs
        iocs = self._safe_run("extract_iocs", self.extract_iocs, text)

        # Stage 2: Geolocate IPs and discover subdomains
        geo_data = self._safe_run("geolocate_iocs", self.geolocate_iocs, iocs)

        # Stage 3: Build entity relationship graph
        entities = self._build_entities(iocs, geo_data)
        links = self._safe_run("analyze_links", self.analyze_links, entities)

        # Stage 4: Temporal analysis
        events = self._build_events(iocs, geo_data)
        temporal = self._safe_run("analyze_temporal", self.analyze_temporal, events)

        # Stage 5: Attribution
        infrastructure = self._build_infrastructure(iocs, geo_data)
        attr = self._safe_run("attribute_actors", self.attribute_actors, infrastructure)

        # Stage 6: Apply analytical frameworks
        fw = self._safe_run("apply_frameworks", self.apply_frameworks, {
            "iocs": iocs,
            "geolocation": geo_data,
            "links": links,
            "temporal": temporal,
            "attribution": attr,
            "text": text,
        })

        # Stage 7: Trace cryptocurrency wallets
        wallets = self._collect_wallets(iocs)
        crypto = self._safe_run("trace_crypto", self.trace_crypto, wallets)

        self._pipeline_log.append({
            "event": "pipeline_complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        return self._findings

    # ------------------------------------------------------------------
    # Stage 1: IOC Extraction
    # ------------------------------------------------------------------

    def extract_iocs(self, text: str) -> dict[str, list[str]]:
        """Extract Indicators of Compromise from text.

        Args:
            text: Raw text to analyze.

        Returns:
            Dictionary mapping IOC type to list of unique values.
        """
        result = self._extractor.extract(text)
        self._findings["iocs"] = result
        return result

    # ------------------------------------------------------------------
    # Stage 2: Geolocation
    # ------------------------------------------------------------------

    def geolocate_iocs(self, iocs: dict[str, list[str]]) -> list[dict]:
        """Geolocate IPs and discover subdomains from extracted IOCs.

        Args:
            iocs: IOC dictionary from extract_iocs().

        Returns:
            List of geolocation result dicts.
        """
        geo_results: list[dict] = []

        # Geolocate IPv4 addresses
        for ip in iocs.get("ipv4", []):
            info = self._geo.geolocate_ip(ip)
            if info:
                geo_results.append(info)

        # Geolocate IPv6 addresses
        for ip in iocs.get("ipv6", []):
            info = self._geo.geolocate_ip(ip)
            if info:
                geo_results.append(info)

        # Discover subdomains for domains
        for domain in iocs.get("domains", []):
            subs = self._geo.discover_subdomains(domain)
            if subs:
                geo_results.append({
                    "domain": domain,
                    "subdomains": subs,
                    "subdomain_count": len(subs),
                })

        # Correlate infrastructure if we have data
        if geo_results:
            try:
                correlated = self._geo.correlate(geo_results)
                if correlated:
                    geo_results.append({"correlation": correlated})
            except Exception as exc:
                _logger.debug("Infrastructure correlation failed: %s", exc)

        self._findings["geolocation"] = geo_results
        return geo_results

    # ------------------------------------------------------------------
    # Stage 3: Link Analysis
    # ------------------------------------------------------------------

    def analyze_links(self, entities: list[dict]) -> dict:
        """Build entity relationship graph and run network analysis.

        Args:
            entities: List of entity dicts with at least an 'id' key.

        Returns:
            Link analysis results with PageRank, betweenness, communities.
        """
        if not entities:
            self._findings["links"] = {"available": False, "reason": "no_entities"}
            return self._findings["links"]

        # Build relationships from entity co-occurrence
        relationships = self._derive_relationships(entities)

        # Build graph
        graph = self._link.build_graph(entities, relationships)

        if graph is None or self._link.node_count == 0:
            self._findings["links"] = {"available": False, "reason": "graph_build_failed"}
            return self._findings["links"]

        # Run analysis algorithms
        summary = self._link.summary()

        self._findings["links"] = summary
        return summary

    # ------------------------------------------------------------------
    # Stage 4: Temporal Analysis
    # ------------------------------------------------------------------

    def analyze_temporal(self, events: list[dict]) -> dict:
        """Perform temporal analysis on events.

        Args:
            events: List of event dicts with 'timestamp' (datetime),
                'event_type', and 'data' keys.

        Returns:
            Temporal analysis results with timeline, anomalies, forecast.
        """
        # Add events to analyzer
        for event in events:
            ts = event.get("timestamp")
            if isinstance(ts, datetime):
                self._temporal.add_event(
                    ts,
                    event.get("event_type", "unknown"),
                    event.get("data", {}),
                )

        # Run analysis
        timeline = self._temporal.get_timeline()
        anomalies = self._temporal.detect_anomalies()
        stats = self._temporal.get_stats()

        result = {
            "timeline": timeline,
            "anomalies": anomalies,
            "stats": stats,
            "anomaly_count": len(anomalies),
        }

        self._findings["temporal"] = result
        return result

    # ------------------------------------------------------------------
    # Stage 5: Attribution
    # ------------------------------------------------------------------

    def attribute_actors(self, infrastructure: list[dict]) -> dict:
        """Perform multi-factor actor attribution.

        Args:
            infrastructure: List of infrastructure indicator dicts.

        Returns:
            Attribution result with confidence score and verdict.
        """
        if not infrastructure:
            self._findings["attribution"] = {
                "available": False,
                "reason": "no_infrastructure",
            }
            return self._findings["attribution"]

        result = self._attribution.attribute(infrastructure)
        self._findings["attribution"] = result
        return result

    # ------------------------------------------------------------------
    # Stage 6: Analytical Frameworks
    # ------------------------------------------------------------------

    def apply_frameworks(self, findings: dict) -> dict:
        """Apply MITRE ATT&CK, Diamond Model, and Kill Chain frameworks.

        Args:
            findings: Consolidated findings from previous stages.

        Returns:
            Framework analysis results.
        """
        text = findings.get("text", "")
        iocs = findings.get("iocs", {})
        attr = findings.get("attribution", {})

        # Build evidence list for framework analysis
        evidence = self._build_evidence(text, iocs)

        # MITRE ATT&CK mapping
        mitre_mapping = self._frameworks.map_attack_techniques(evidence)

        # Diamond Model
        diamond_evidence = {
            "description": text,
            "ips": iocs.get("ipv4", []) + iocs.get("ipv6", []),
            "domains": iocs.get("domains", []),
        }
        diamond = self._frameworks.diamond_model(diamond_evidence)

        # Cyber Kill Chain
        kill_chain = self._frameworks.kill_chain({
            "description": text,
            "indicators": iocs.get("urls", []) + iocs.get("domains", []),
        })

        result = {
            "mitre_mapping": mitre_mapping,
            "diamond": diamond,
            "kill_chain": kill_chain,
            "technique_count": sum(
                len(e.get("techniques", [])) for e in mitre_mapping
            ),
        }

        self._findings["frameworks"] = result
        return result

    # ------------------------------------------------------------------
    # Stage 7: Crypto Tracing
    # ------------------------------------------------------------------

    def trace_crypto(self, wallets: list[str]) -> dict:
        """Trace cryptocurrency wallets.

        Args:
            wallets: List of wallet addresses (BTC or ETH).

        Returns:
            Crypto tracing results per wallet.
        """
        if not wallets:
            self._findings["crypto"] = {"available": False, "reason": "no_wallets"}
            return self._findings["crypto"]

        results: dict[str, Any] = {}

        for wallet in wallets:
            if wallet.startswith("0x") and len(wallet) == 42:
                # ETH address
                trace = self._crypto.trace_eth(wallet, depth=1)
                results[wallet] = trace
            else:
                # Assume BTC
                trace = self._crypto.trace_btc(wallet, depth=1)
                results[wallet] = trace

        self._findings["crypto"] = results
        return results

    # ------------------------------------------------------------------
    # Report Generation
    # ------------------------------------------------------------------

    def generate_report(self) -> str:
        """Generate a consolidated Markdown report from all findings.

        Returns:
            Markdown-formatted investigation report string.
        """
        sections: list[str] = []

        # Header
        sections.append(f"# Investigation Report: {self.investigation_id}")
        sections.append(f"\n**Created:** {self.created_at.isoformat()}")
        sections.append(f"**Source:** {self.metadata.get('source', 'N/A')}")
        sections.append(f"**TLP:** {self.metadata.get('tlp', 'WHITE')}")
        sections.append(f"**Analyst:** {self.metadata.get('analyst', 'ARGUS Intelligence')}")

        # Executive Summary
        sections.append("\n## Executive Summary\n")
        sections.append(self._build_executive_summary())

        # IOCs
        sections.append("\n## Indicators of Compromise\n")
        sections.append(self._format_iocs())

        # Geolocation
        sections.append("\n## Geolocation & Infrastructure\n")
        sections.append(self._format_geolocation())

        # Link Analysis
        sections.append("\n## Entity Relationship Analysis\n")
        sections.append(self._format_links())

        # Temporal Analysis
        sections.append("\n## Temporal Analysis\n")
        sections.append(self._format_temporal())

        # Attribution
        sections.append("\n## Attribution\n")
        sections.append(self._format_attribution())

        # Frameworks
        sections.append("\n## Analytical Frameworks\n")
        sections.append(self._format_frameworks())

        # Crypto
        sections.append("\n## Cryptocurrency Tracing\n")
        sections.append(self._format_crypto())

        # Pipeline Log
        sections.append("\n## Pipeline Execution Log\n")
        sections.append(self._format_pipeline_log())

        # Footer
        sections.append("\n---")
        sections.append(
            f"*Generated by ARGUS Investigation Orchestrator — "
            f"{datetime.now(timezone.utc).isoformat()}*"
        )

        return "\n".join(sections)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_findings(self) -> dict[str, Any]:
        """Return all accumulated findings.

        Returns:
            Complete findings dictionary from all pipeline stages.
        """
        return dict(self._findings)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _safe_run(
        self,
        stage_name: str,
        func: callable,
        *args: Any,
    ) -> Any:
        """Execute a pipeline stage with error handling.

        If the stage fails, log the error and return an empty result
        so the pipeline can continue.
        """
        try:
            result = func(*args)
            self._pipeline_log.append({
                "event": "stage_complete",
                "stage": stage_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "success": True,
            })
            return result
        except Exception as exc:
            _logger.warning("Pipeline stage '%s' failed: %s", stage_name, exc)
            self._pipeline_log.append({
                "event": "stage_error",
                "stage": stage_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "success": False,
                "error": str(exc),
            })
            return {}

    def _build_entities(self, iocs: dict, geo_data: list[dict]) -> list[dict]:
        """Build entity list from IOCs and geolocation data."""
        entities: list[dict] = []
        seen_ids: set[str] = set()

        # Add IP entities
        for ip in iocs.get("ipv4", []) + iocs.get("ipv6", []):
            if ip not in seen_ids:
                entities.append({"id": ip, "type": "ip", "label": ip})
                seen_ids.add(ip)

        # Add domain entities
        for domain in iocs.get("domains", []):
            if domain not in seen_ids:
                entities.append({"id": domain, "type": "domain", "label": domain})
                seen_ids.add(domain)

        # Add NER entities
        for entity in iocs.get("entities", []):
            text = entity.get("text", "")
            if text and text not in seen_ids:
                entities.append({
                    "id": text,
                    "type": entity.get("label", "unknown").lower(),
                    "label": text,
                })
                seen_ids.add(text)

        # Add geolocated IPs with org info
        for geo in geo_data:
            if isinstance(geo, dict) and geo.get("ip"):
                ip = geo["ip"]
                for ent in entities:
                    if ent["id"] == ip:
                        ent["country"] = geo.get("country", "")
                        ent["org"] = geo.get("org", "")

        return entities

    def _derive_relationships(
        self, entities: list[dict]
    ) -> list[tuple[str, str, dict | None]]:
        """Derive relationships between entities for graph building."""
        relationships: list[tuple[str, str, dict | None]] = []

        # Group entities by country/org for relationship inference
        by_country: dict[str, list[str]] = {}
        by_org: dict[str, list[str]] = {}

        for ent in entities:
            country = ent.get("country", "")
            org = ent.get("org", "")
            if country:
                by_country.setdefault(country, []).append(ent["id"])
            if org:
                by_org.setdefault(org, []).append(ent["id"])

        # Create relationships for entities sharing country
        for country, ids in by_country.items():
            if len(ids) > 1:
                for i in range(len(ids)):
                    for j in range(i + 1, len(ids)):
                        relationships.append((ids[i], ids[j], {
                            "type": "shared_country",
                            "value": country,
                        }))

        # Create relationships for entities sharing org
        for org, ids in by_org.items():
            if len(ids) > 1:
                for i in range(len(ids)):
                    for j in range(i + 1, len(ids)):
                        relationships.append((ids[i], ids[j], {
                            "type": "shared_org",
                            "value": org,
                        }))

        return relationships

    def _build_events(self, iocs: dict, geo_data: list[dict]) -> list[dict]:
        """Build temporal events from IOCs and geolocation data."""
        events: list[dict] = []
        now = datetime.now(timezone.utc)

        # Create events for each IOC type
        for ip in iocs.get("ipv4", []):
            events.append({
                "timestamp": now,
                "event_type": "ioc_discovered",
                "data": {"type": "ipv4", "value": ip},
            })

        for domain in iocs.get("domains", []):
            events.append({
                "timestamp": now,
                "event_type": "ioc_discovered",
                "data": {"type": "domain", "value": domain},
            })

        for url in iocs.get("urls", []):
            events.append({
                "timestamp": now,
                "event_type": "ioc_discovered",
                "data": {"type": "url", "value": url},
            })

        # Add geolocation events
        for geo in geo_data:
            if isinstance(geo, dict) and geo.get("ip"):
                events.append({
                    "timestamp": now,
                    "event_type": "geo_located",
                    "data": {
                        "ip": geo.get("ip"),
                        "country": geo.get("country"),
                        "org": geo.get("org"),
                    },
                })

        return events

    def _build_infrastructure(self, iocs: dict, geo_data: list[dict]) -> list[dict]:
        """Build infrastructure indicators for attribution."""
        infrastructure: list[dict] = []

        # Add IPs as infrastructure
        for ip in iocs.get("ipv4", []):
            infrastructure.append({
                "type": "ip",
                "host": ip,
            })

        # Add domains as infrastructure
        for domain in iocs.get("domains", []):
            infrastructure.append({
                "type": "domain",
                "host": domain,
            })

        # Add geolocated data
        for geo in geo_data:
            if isinstance(geo, dict) and geo.get("ip"):
                infrastructure.append({
                    "type": "geo",
                    "ip": geo.get("ip"),
                    "country": geo.get("country", ""),
                    "org": geo.get("org", ""),
                    "asn": geo.get("asn", ""),
                })

        # Add PGP keys
        for key in iocs.get("pgp_keys", []):
            infrastructure.append({
                "type": "pgp",
                "key": key,
            })

        return infrastructure

    def _collect_wallets(self, iocs: dict) -> list[str]:
        """Collect cryptocurrency wallet addresses from IOCs."""
        wallets: list[str] = []
        wallets.extend(iocs.get("btc", []))
        wallets.extend(iocs.get("eth", []))
        return wallets

    def _build_evidence(self, text: str, iocs: dict) -> list[dict]:
        """Build evidence list for framework analysis."""
        evidence: list[dict] = []

        if text:
            evidence.append({
                "description": text[:500],
                "type": "raw_text",
                "reliability": "medium",
            })

        # Add IOC-based evidence
        for ip in iocs.get("ipv4", []):
            evidence.append({
                "description": f"IPv4 address {ip} identified in investigation",
                "type": "ip",
                "value": ip,
                "reliability": "high",
            })

        for domain in iocs.get("domains", []):
            evidence.append({
                "description": f"Domain {domain} identified in investigation",
                "type": "domain",
                "value": domain,
                "reliability": "high",
            })

        for cve in iocs.get("cves", []):
            evidence.append({
                "description": f"Vulnerability {cve} referenced",
                "type": "cve",
                "value": cve,
                "reliability": "high",
            })

        return evidence

    # ------------------------------------------------------------------
    # Report formatters
    # ------------------------------------------------------------------

    def _build_executive_summary(self) -> str:
        """Build executive summary from findings."""
        parts: list[str] = []

        ioc_count = sum(
            len(v) for v in self._findings["iocs"].values()
            if isinstance(v, list)
        )
        parts.append(f"- **Total IOCs extracted:** {ioc_count}")

        geo_count = len(self._findings.get("geolocation", []))
        if geo_count:
            parts.append(f"- **Geolocated indicators:** {geo_count}")

        links = self._findings.get("links", {})
        if links.get("available"):
            parts.append(
                f"- **Entity graph:** {links.get('node_count', 0)} nodes, "
                f"{links.get('edge_count', 0)} edges"
            )

        temporal = self._findings.get("temporal", {})
        if temporal.get("anomaly_count"):
            parts.append(f"- **Temporal anomalies detected:** {temporal['anomaly_count']}")

        attr = self._findings.get("attribution", {})
        if attr.get("verdict"):
            parts.append(f"- **Attribution verdict:** {attr['verdict']}")
            parts.append(f"- **Confidence:** {attr.get('confidence', 0):.1%}")

        fw = self._findings.get("frameworks", {})
        if fw.get("technique_count"):
            parts.append(f"- **MITRE techniques mapped:** {fw['technique_count']}")

        crypto = self._findings.get("crypto", {})
        if crypto.get("available") is not False and crypto:
            wallet_count = len(crypto)
            parts.append(f"- **Crypto wallets traced:** {wallet_count}")

        return "\n".join(parts) if parts else "No significant findings."

    def _format_iocs(self) -> str:
        """Format IOCs section."""
        iocs = self._findings.get("iocs", {})
        if not iocs:
            return "No IOCs extracted."

        lines: list[str] = []
        ioc_labels = {
            "urls": "URLs",
            "ipv4": "IPv4 Addresses",
            "ipv6": "IPv6 Addresses",
            "domains": "Domains",
            "md5": "MD5 Hashes",
            "sha1": "SHA1 Hashes",
            "sha256": "SHA256 Hashes",
            "sha512": "SHA512 Hashes",
            "emails": "Email Addresses",
            "cves": "CVE Identifiers",
            "onion_v2": "Onion v2 Addresses",
            "onion_v3": "Onion v3 Addresses",
            "btc": "Bitcoin Addresses",
            "eth": "Ethereum Addresses",
            "pgp_keys": "PGP Key Fingerprints",
            "entities": "Named Entities",
        }

        for key, label in ioc_labels.items():
            values = iocs.get(key, [])
            if not values:
                continue
            lines.append(f"\n### {label} ({len(values)})\n")
            if key == "entities":
                for ent in values:
                    lines.append(f"- **{ent.get('text', '')}** ({ent.get('label', 'unknown')})")
            else:
                for v in values[:50]:  # Limit display
                    lines.append(f"- `{v}`")
                if len(values) > 50:
                    lines.append(f"- *... and {len(values) - 50} more*")

        return "\n".join(lines) if lines else "No IOCs found."

    def _format_geolocation(self) -> str:
        """Format geolocation section."""
        geo_data = self._findings.get("geolocation", [])
        if not geo_data:
            return "No geolocation data available."

        lines: list[str] = []
        for geo in geo_data:
            if not isinstance(geo, dict):
                continue
            if geo.get("ip"):
                lines.append(f"\n### {geo['ip']}\n")
                if geo.get("city") or geo.get("region"):
                    lines.append(f"- **Location:** {geo.get('city', 'N/A')}, {geo.get('region', 'N/A')}")
                if geo.get("country"):
                    lines.append(f"- **Country:** {geo['country']}")
                if geo.get("org"):
                    lines.append(f"- **Organization:** {geo['org']}")
                if geo.get("loc"):
                    lines.append(f"- **Coordinates:** {geo['loc']}")
            elif geo.get("domain"):
                lines.append(f"\n### {geo['domain']} (Subdomains)\n")
                subs = geo.get("subdomains", [])
                lines.append(f"- **Count:** {len(subs)}")
                for sub in subs[:20]:
                    lines.append(f"  - `{sub}`")
                if len(subs) > 20:
                    lines.append(f"  - *... and {len(subs) - 20} more*")
            elif "correlation" in geo:
                corr = geo["correlation"]
                summary = corr.get("summary", {})
                lines.append(f"\n### Infrastructure Correlation\n")
                lines.append(f"- **Unique organizations:** {summary.get('unique_orgs', 0)}")
                lines.append(f"- **Unique ASNs:** {summary.get('unique_asns', 0)}")
                lines.append(f"- **Unique countries:** {summary.get('unique_countries', 0)}")
                lines.append(f"- **Relationships found:** {summary.get('relationships_found', 0)}")

        return "\n".join(lines) if lines else "No geolocation data."

    def _format_links(self) -> str:
        """Format link analysis section."""
        links = self._findings.get("links", {})
        if not links.get("available"):
            return "Link analysis not available (no entities or NetworkX missing)."

        lines: list[str] = []
        lines.append(f"- **Nodes:** {links.get('node_count', 0)}")
        lines.append(f"- **Edges:** {links.get('edge_count', 0)}")
        lines.append(f"- **Density:** {links.get('density', 0):.4f}")
        lines.append(f"- **Connected:** {links.get('is_connected', False)}")

        top_pr = links.get("top_pagerank", {})
        if top_pr:
            lines.append(f"\n### Top PageRank Nodes\n")
            for node, score in list(top_pr.items())[:10]:
                lines.append(f"- **{node}** — score: {score:.4f}")

        top_bet = links.get("top_betweenness", {})
        if top_bet:
            lines.append(f"\n### Top Betweenness Nodes\n")
            for node, score in list(top_bet.items())[:10]:
                lines.append(f"- **{node}** — score: {score:.4f}")

        communities = links.get("communities", {})
        if communities:
            lines.append(f"\n### Communities ({len(communities)})\n")
            for comm_id, members in communities.items():
                lines.append(f"- **{comm_id}**: {', '.join(members[:10])}")
                if len(members) > 10:
                    lines.append(f"  - *... and {len(members) - 10} more*")

        return "\n".join(lines)

    def _format_temporal(self) -> str:
        """Format temporal analysis section."""
        temporal = self._findings.get("temporal", {})
        if not temporal:
            return "No temporal analysis performed."

        lines: list[str] = []
        stats = temporal.get("stats", {})
        if stats:
            lines.append(f"- **Total events:** {stats.get('total_events', 0)}")
            lines.append(f"- **Event types:** {', '.join(stats.get('event_types', []))}")
            time_range = stats.get("time_range")
            if time_range:
                lines.append(f"- **Time range:** {time_range.get('start', 'N/A')} to {time_range.get('end', 'N/A')}")

        anomalies = temporal.get("anomalies", [])
        if anomalies:
            lines.append(f"\n### Anomalies Detected ({len(anomalies)})\n")
            for a in anomalies[:10]:
                lines.append(
                    f"- **{a.get('event_type', 'unknown')}** at {a.get('hour', 'N/A')} — "
                    f"count: {a.get('count', 0)}, z-score: {a.get('z_score', 0)}"
                )

        return "\n".join(lines) if lines else "No temporal data."

    def _format_attribution(self) -> str:
        """Format attribution section."""
        attr = self._findings.get("attribution", {})
        if attr.get("available") is False:
            return "Attribution not available (no infrastructure indicators)."

        lines: list[str] = []
        lines.append(f"- **Verdict:** {attr.get('verdict', 'N/A')}")
        lines.append(f"- **Confidence:** {attr.get('confidence', 0):.1%}")

        factors = attr.get("factors", [])
        if factors:
            lines.append(f"\n### Attribution Factors\n")
            for f in factors:
                match_str = "✓" if f.get("match") else "✗"
                lines.append(
                    f"- [{match_str}] **{f.get('type', 'unknown')}** — "
                    f"confidence: {f.get('confidence', 0):.1%}"
                )

        correlations = attr.get("correlations", {})
        if correlations.get("pgp"):
            pgp = correlations["pgp"]
            if pgp.get("clusters"):
                lines.append(f"\n### PGP Key Clusters\n")
                for cluster in pgp["clusters"]:
                    lines.append(
                        f"- Cluster {cluster.get('cluster_id', 0)}: "
                        f"{cluster.get('key_count', 0)} keys"
                    )

        return "\n".join(lines) if lines else "No attribution data."

    def _format_frameworks(self) -> str:
        """Format analytical frameworks section."""
        fw = self._findings.get("frameworks", {})
        if not fw:
            return "No framework analysis performed."

        lines: list[str] = []

        # MITRE ATT&CK
        mitre = fw.get("mitre_mapping", [])
        if mitre:
            lines.append(f"\n### MITRE ATT&CK Techniques ({fw.get('technique_count', 0)})\n")
            for entry in mitre:
                for tech in entry.get("techniques", [])[:5]:
                    lines.append(
                        f"- **{tech['id']}** ({tech['name']}) — "
                        f"Tactic: {tech['tactic']} — "
                        f"Confidence: {tech['confidence']:.0%}"
                    )

        # Diamond Model
        diamond = fw.get("diamond", {})
        if diamond:
            lines.append(f"\n### Diamond Model\n")
            adv = diamond.get("adversary", {})
            lines.append(f"- **Adversary:** {adv.get('identified', 'Unknown')} ({adv.get('type', 'Unknown')})")
            lines.append(f"- **Motivation:** {adv.get('motivation', 'Unknown')}")
            cap = diamond.get("capability", {})
            lines.append(f"- **Sophistication:** {cap.get('sophistication', 'Unknown')}")
            infra = diamond.get("infrastructure", {})
            lines.append(f"- **Infrastructure type:** {infra.get('infrastructure_type', 'Unknown')}")

        # Kill Chain
        kc = fw.get("kill_chain", {})
        if kc:
            lines.append(f"\n### Cyber Kill Chain\n")
            lines.append(f"- **Highest active phase:** {kc.get('highest_active_phase', 0)}")
            lines.append(f"- **Assessment:** {kc.get('assessment', 'N/A')}")
            for phase in kc.get("phases", []):
                status = "✅" if phase.get("active") else "⬜"
                lines.append(f"- {status} **{phase['phase']}**")

        return "\n".join(lines) if lines else "No framework data."

    def _format_crypto(self) -> str:
        """Format cryptocurrency tracing section."""
        crypto = self._findings.get("crypto", {})
        if crypto.get("available") is False:
            return "No cryptocurrency wallets to trace."

        if not crypto:
            return "No crypto tracing performed."

        lines: list[str] = []
        for wallet, trace in crypto.items():
            if not isinstance(trace, dict):
                continue
            lines.append(f"\n### `{wallet}`\n")
            lines.append(f"- **Chain:** {trace.get('chain', 'Unknown')}")
            lines.append(f"- **Transactions:** {len(trace.get('transactions', []))}")
            lines.append(f"- **Peers:** {len(trace.get('peers', []))}")
            lines.append(f"- **Depth reached:** {trace.get('depth_reached', 0)}")
            if trace.get("exchange"):
                lines.append(f"- **Exchange:** {', '.join(trace['exchange'])}")

        return "\n".join(lines) if lines else "No crypto data."

    def _format_pipeline_log(self) -> str:
        """Format pipeline execution log."""
        lines: list[str] = []
        for entry in self._pipeline_log:
            status = "✓" if entry.get("success", True) else "✗"
            stage = entry.get("stage", entry.get("event", "unknown"))
            ts = entry.get("timestamp", "")
            lines.append(f"- [{status}] **{stage}** — {ts}")
            if entry.get("error"):
                lines.append(f"  - Error: {entry['error']}")

        return "\n".join(lines) if lines else "No pipeline log entries."
