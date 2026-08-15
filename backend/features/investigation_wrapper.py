"""InvestigationOrchestrator wrapper — exposes run_full_pipeline via thread pool.

Wraps ARGUS's InvestigationOrchestrator to run the full intelligence pipeline
asynchronously using asyncio's thread pool executor, preventing blocking of
the event loop during CPU-intensive analysis stages.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from argus_engine.intel.investigation import InvestigationOrchestrator

logger = logging.getLogger(__name__)

# Shared thread pool for investigation pipelines
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="investigation")


class InvestigationWrapper:
    """Async wrapper around ARGUS's InvestigationOrchestrator.

    Runs the full pipeline in a thread pool to avoid blocking the
    asyncio event loop. Each invocation creates a fresh orchestrator
    instance with a unique investigation ID.

    Usage::

        wrapper = InvestigationWrapper()
        result = await wrapper.run_full_pipeline("Check http://evil.com")
        report = await wrapper.generate_report()
    """

    def __init__(self, investigation_id: str | None = None) -> None:
        """Initialize the wrapper.

        Args:
            investigation_id: Optional UUID for the investigation.
                Auto-generated if not provided.
        """
        self._investigation_id = investigation_id
        self._orchestrator: InvestigationOrchestrator | None = None

    @property
    def investigation_id(self) -> str | None:
        """Return the investigation ID from the last run."""
        if self._orchestrator is not None:
            return self._orchestrator.investigation_id
        return self._investigation_id

    async def run_full_pipeline(
        self,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full investigation pipeline asynchronously.

        Runs all intelligence modules (IOC extraction, geolocation,
        link analysis, temporal analysis, attribution, frameworks,
        crypto tracing) in a thread pool.

        Args:
            text: Raw text to investigate.
            metadata: Optional metadata (source, TLP, analyst, etc.).

        Returns:
            Consolidated findings dict from all pipeline stages.
        """
        loop = asyncio.get_running_loop()

        def _run() -> dict[str, Any]:
            self._orchestrator = InvestigationOrchestrator(
                investigation_id=self._investigation_id,
            )
            return self._orchestrator.run_full_pipeline(text, metadata)

        logger.info("Starting investigation pipeline (text_length=%d)", len(text))
        result = await loop.run_in_executor(_executor, _run)
        logger.info(
            "Investigation pipeline complete (id=%s)",
            self._orchestrator.investigation_id if self._orchestrator else "unknown",
        )
        return result

    async def generate_report(self) -> str:
        """Generate a Markdown report from the last pipeline run.

        Returns:
            Markdown-formatted investigation report.

        Raises:
            RuntimeError: If no pipeline has been run yet.
        """
        if self._orchestrator is None:
            raise RuntimeError("No investigation has been run yet. Call run_full_pipeline() first.")

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _executor,
            self._orchestrator.generate_report,
        )

    async def get_findings(self) -> dict[str, Any]:
        """Return all accumulated findings from the last pipeline run.

        Returns:
            Complete findings dictionary.

        Raises:
            RuntimeError: If no pipeline has been run yet.
        """
        if self._orchestrator is None:
            raise RuntimeError("No investigation has been run yet. Call run_full_pipeline() first.")

        return self._orchestrator.get_findings()

    @staticmethod
    def shutdown() -> None:
        """Shutdown the thread pool executor."""
        _executor.shutdown(wait=False)
        logger.info("Investigation thread pool shut down")
