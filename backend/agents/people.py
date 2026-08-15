"""PeopleFinder agent — username/email/phone search.

Wraps argus_engine/search.py for searching people across platforms and databases.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import time
from typing import Any

from backend.agents.base import BaseAgent
from backend.core.config import settings

logger = logging.getLogger(__name__)


class PeopleFinder(BaseAgent):
    """People search agent — username/email/phone investigation.

    Searches for individuals across platforms using argus_engine/search.py
    dark web engines and surface web sources.
    """

    name = "people_finder"
    description = "People search — finds individuals by username, email, or phone across platforms and databases"
    capabilities = [
        "username_search",
        "email_search",
        "phone_search",
        "social_media_search",
        "people_investigation",
    ]

    async def run(self, task: dict[str, Any]) -> dict[str, Any]:
        """Execute people search.

        Task dict keys:
            - query (str): Search term — username, email, or phone (required)
            - search_type (str): "username", "email", "phone", or "auto" (default: auto)
            - max_workers (int): Concurrent search threads (default: 5)
            - platforms (list): Specific platforms to search (not yet implemented)

        Returns:
            dict with keys: query, search_type, results, count
        """
        start = time.monotonic()
        query = task.get("query", "")
        if not query:
            return self._error_result("Missing required 'query' parameter")

        search_type = task.get("search_type", "auto")
        max_workers = task.get("max_workers", 5)

        # Auto-detect search type
        if search_type == "auto":
            search_type = self._detect_search_type(query)

        result: dict[str, Any] = {
            "agent_name": self.name,
            "query": query,
            "search_type": search_type,
            "results": [],
        }

        loop = asyncio.get_event_loop()

        # Search via argus_engine/search.py
        search_data = await loop.run_in_executor(
            None, self._search_people, query, search_type, max_workers
        )
        result["results"] = search_data.get("results", [])
        result["search_status"] = search_data.get("status", "unknown")
        result["count"] = len(result["results"])

        elapsed = (time.monotonic() - start) * 1000
        result["execution_time_ms"] = round(elapsed, 2)
        result["status"] = "completed"
        return result

    def _detect_search_type(self, query: str) -> str:
        """Auto-detect the type of search query."""
        import re

        if re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", query):
            return "email"
        if re.match(r"^[\+]?[\d\s\-\(\)]{7,20}$", query):
            return "phone"
        return "username"

    def _search_people(
        self, query: str, search_type: str, max_workers: int
    ) -> dict[str, Any]:
        """Search with installed OSINT packages plus the multi-engine index."""
        results: list[dict[str, Any]] = []
        native = self._run_native_package(query, search_type)
        if native:
            results.append(native)
        try:
            from argus_engine.search import get_search_results

            results.extend(get_search_results(query, max_workers=max_workers))
            return {"status": "completed", "results": results, "count": len(results)}
        except ImportError:
            logger.warning("argus_engine.search not available")
            return {
                "status": "degraded",
                "results": results,
                "error": "argus_engine.search module not available",
            }
        except Exception as exc:
            logger.exception("People search failed")
            return {
                "status": "degraded" if results else "failed",
                "results": results,
                "error": str(exc),
            }

    @staticmethod
    def _run_native_package(query: str, search_type: str) -> dict[str, Any] | None:
        """Invoke known passive packages without a shell; output is bounded."""
        if search_type == "username" and shutil.which("sherlock"):
            command = [
                "sherlock", query, "--proxy", settings.tor_proxy,
                "--print-found", "--no-color",
            ]
            package = "sherlock"
        else:
            return None
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"source": package, "status": "failed", "error": str(exc)[:500]}
        output = (completed.stdout or completed.stderr or "").strip()
        return {
            "source": package,
            "status": "completed" if completed.returncode == 0 else "failed",
            "exit_code": completed.returncode,
            "output": output[:20_000],
            "truncated": len(output) > 20_000,
        }

    def _error_result(self, message: str) -> dict[str, Any]:
        return {
            "agent_name": self.name,
            "status": "failed",
            "error": message,
            "results": [],
        }
