"""ReportWriter agent — investigation report generation.

Wraps argus_engine/intel/investigation.py InvestigationOrchestrator for
generating consolidated investigation reports.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from backend.agents.base import BaseAgent
from backend.agents.context import evidence_text

logger = logging.getLogger(__name__)


class ReportWriter(BaseAgent):
    """Investigation report generation agent.

    Generates consolidated investigation reports from findings using
    argus_engine/intel/investigation.py InvestigationOrchestrator.
    """

    name = "report_writer"
    description = "Report generation — generates consolidated investigation reports from findings and IOCs"
    capabilities = [
        "report_generation",
        "investigation_summary",
        "markdown_report",
        "findings_consolidation",
    ]

    async def run(self, task: dict[str, Any]) -> dict[str, Any]:
        """Execute report generation.

        Task dict keys:
            - text (str): Raw text/findings to analyze (required)
            - metadata (dict): Report metadata (source, TLP, analyst, etc.)
            - investigation_id (str): Optional investigation ID

        Returns:
            dict with keys: report (str), findings (dict), investigation_id
        """
        start = time.monotonic()
        text = evidence_text(task)
        if not text:
            return self._error_result("Missing required 'text' parameter")

        metadata = task.get("metadata", {})
        investigation_id = task.get("investigation_id")

        result: dict[str, Any] = {
            "agent_name": self.name,
            "report": "",
            "findings": {},
        }

        loop = asyncio.get_event_loop()

        # Generate report via argus_engine/intel/investigation.py
        report_data = await loop.run_in_executor(
            None, self._generate_report, text, metadata, investigation_id
        )
        result["report"] = report_data.get("report", "")
        result["findings"] = report_data.get("findings", {})
        result["investigation_id"] = report_data.get("investigation_id", "")
        result["report_status"] = report_data.get("status", "unknown")

        elapsed = (time.monotonic() - start) * 1000
        result["execution_time_ms"] = round(elapsed, 2)
        result["status"] = "completed"
        return result

    def _generate_report(
        self,
        text: str,
        metadata: dict[str, Any],
        investigation_id: str | None,
    ) -> dict[str, Any]:
        """Generate report via argus_engine/intel/investigation.py."""
        try:
            from argus_engine.intel.investigation import InvestigationOrchestrator

            orchestrator = InvestigationOrchestrator(
                investigation_id=investigation_id
            )
            findings = orchestrator.run_full_pipeline(text, metadata=metadata)
            report = orchestrator.generate_report()

            return {
                "status": "completed",
                "report": report,
                "findings": findings,
                "investigation_id": orchestrator.investigation_id,
            }
        except ImportError:
            logger.warning("argus_engine.intel.investigation not available")
            return {
                "status": "degraded",
                "report": "",
                "findings": {},
                "error": "InvestigationOrchestrator not available",
            }
        except Exception as exc:
            logger.exception("Report generation failed")
            return {
                "status": "failed",
                "report": "",
                "findings": {},
                "error": str(exc),
            }

    def _error_result(self, message: str) -> dict[str, Any]:
        return {
            "agent_name": self.name,
            "status": "failed",
            "error": message,
            "report": "",
            "findings": {},
        }
