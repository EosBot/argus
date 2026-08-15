"""ThreatIntelAnalyst agent — threat attribution + IOC analysis.

Wraps argus_engine/intel/attribution.py (multi-factor attribution) and
argus_engine/intel/ioc_extractor.py (IOC extraction).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from backend.agents.base import BaseAgent
from backend.agents.context import evidence_text

logger = logging.getLogger(__name__)


class ThreatIntelAnalyst(BaseAgent):
    """Threat intelligence analysis agent.

    Performs multi-factor actor attribution using JA4+ fingerprints,
    favicon hashes, JARM TLS signatures, and PGP key correlation.
    Also extracts and analyzes IOCs for threat context.
    """

    name = "threat_intel_analyst"
    description = "Threat intelligence — multi-factor actor attribution, IOC analysis, infrastructure correlation"
    capabilities = [
        "actor_attribution",
        "ja4_fingerprinting",
        "jarm_fingerprinting",
        "favicon_hashing",
        "pgp_correlation",
        "threat_analysis",
        "ioc_analysis",
    ]

    async def run(self, task: dict[str, Any]) -> dict[str, Any]:
        """Execute threat intelligence analysis.

        Task dict keys:
            - indicators (list): Infrastructure indicator dicts (required)
                Each dict should have: type (tls/favicon/jarm/pgp/domain/ip),
                host/url/key as appropriate
            - text (str): Optional text to extract IOCs from first
            - calculate_confidence (bool): Whether to calc confidence (default: true)

        Returns:
            dict with keys: attribution, iocs, confidence, verdict
        """
        start = time.monotonic()
        indicators = task.get("indicators", [])
        text = evidence_text(task)

        if not indicators and not text:
            return self._error_result("Missing required 'indicators' or 'text' parameter")

        result: dict[str, Any] = {
            "agent_name": self.name,
            "attribution": {},
            "iocs": {},
        }

        loop = asyncio.get_event_loop()

        # Step 1: Extract IOCs from text if provided
        if text:
            ioc_data = await loop.run_in_executor(
                None, self._extract_iocs, text
            )
            result["iocs"] = ioc_data.get("iocs", {})

            # Build indicators from IOCs if none provided
            if not indicators:
                indicators = self._build_indicators_from_iocs(result["iocs"])

        # Step 2: Perform attribution
        attr_data = await loop.run_in_executor(
            None, self._attribute_actors, indicators
        )
        result["attribution"] = attr_data
        result["confidence"] = attr_data.get("confidence", 0.0)
        result["verdict"] = attr_data.get("verdict", "no_attribution")

        elapsed = (time.monotonic() - start) * 1000
        result["execution_time_ms"] = round(elapsed, 2)
        result["status"] = "completed"
        return result

    def _extract_iocs(self, text: str) -> dict[str, Any]:
        """Extract IOCs via argus_engine/intel/ioc_extractor.py."""
        try:
            from argus_engine.intel.ioc_extractor import IOCExtractor

            extractor = IOCExtractor()
            iocs = extractor.extract(text)
            return {"status": "completed", "iocs": iocs}
        except ImportError:
            logger.warning("argus_engine.intel.ioc_extractor not available")
            return {"status": "degraded", "iocs": {}, "error": "IOCExtractor not available"}
        except Exception as exc:
            logger.exception("IOC extraction failed")
            return {"status": "failed", "iocs": {}, "error": str(exc)}

    def _attribute_actors(self, indicators: list[dict]) -> dict[str, Any]:
        """Perform attribution via argus_engine/intel/attribution.py."""
        try:
            from argus_engine.intel.attribution import AttributionEngine

            engine = AttributionEngine()
            return engine.attribute(indicators)
        except ImportError:
            logger.warning("argus_engine.intel.attribution not available")
            return {"error": "AttributionEngine not available"}
        except Exception as exc:
            logger.exception("Attribution failed")
            return {"error": str(exc)}

    def _build_indicators_from_iocs(self, iocs: dict[str, list[str]]) -> list[dict]:
        """Build infrastructure indicators from extracted IOCs."""
        indicators: list[dict[str, Any]] = []

        for ip in iocs.get("ipv4", []):
            indicators.append({"type": "ip", "host": ip})

        for domain in iocs.get("domains", []):
            indicators.append({"type": "domain", "host": domain})

        for key in iocs.get("pgp_keys", []):
            indicators.append({"type": "pgp", "key": key})

        return indicators

    def _error_result(self, message: str) -> dict[str, Any]:
        return {
            "agent_name": self.name,
            "status": "failed",
            "error": message,
            "attribution": {},
            "iocs": {},
        }
