"""OSINTCollector agent — general OSINT data collection.

Wraps argus_engine/search.py and argus_engine/scrape.py for general-purpose OSINT
investigation (surface web search + content extraction).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from backend.agents.base import BaseAgent

logger = logging.getLogger(__name__)


class OSINTCollector(BaseAgent):
    """General OSINT collection agent.

    Performs surface web search and content extraction for
    open-source intelligence gathering.
    """

    name = "osint_collector"
    description = "OSINT collection — surface web search, content extraction, general investigation"
    capabilities = [
        "web_search",
        "content_extraction",
        "surface_web_scraping",
        "osint_gathering",
        "information_collection",
    ]

    async def run(self, task: dict[str, Any]) -> dict[str, Any]:
        """Execute OSINT collection.

        Task dict keys:
            - query (str): Search query (required)
            - max_workers (int): Concurrent threads (default: 5)
            - scrape_results (bool): Whether to scrape found URLs (default: true)
            - max_scrape (int): Max URLs to scrape (default: 5)

        Returns:
            dict with keys: query, results, scraped, count
        """
        start = time.monotonic()
        query = task.get("query", "")
        if not query:
            return self._error_result("Missing required 'query' parameter")

        max_workers = task.get("max_workers", 5)
        scrape_results = task.get("scrape_results", True)
        max_scrape = task.get("max_scrape", 5)

        result: dict[str, Any] = {
            "agent_name": self.name,
            "query": query,
            "results": [],
            "scraped": {},
        }

        loop = asyncio.get_event_loop()

        # Step 1: Search
        search_data = await loop.run_in_executor(
            None, self._search, query, max_workers
        )
        result["results"] = search_data.get("results", [])
        result["search_status"] = search_data.get("status", "unknown")

        # Step 2: Scrape top results
        if scrape_results and result["results"]:
            urls_to_scrape = result["results"][:max_scrape]
            scraped = await loop.run_in_executor(
                None, self._scrape, urls_to_scrape, max_workers
            )
            result["scraped"] = scraped

        result["count"] = len(result["results"])

        elapsed = (time.monotonic() - start) * 1000
        result["execution_time_ms"] = round(elapsed, 2)
        result["status"] = "completed"
        return result

    def _search(self, query: str, max_workers: int) -> dict[str, Any]:
        """Search the clear web through the configured ARGUS enrichment backend."""
        try:
            from argus_engine.clearweb import ClearwebSearch

            search = ClearwebSearch()
            if not search.is_available():
                return {"status": "degraded", "results": [], "error": "No clear-web search backend is installed"}
            raw = search.search(query, max_results=max(max_workers * 2, 5))
            results = [{"title": item.get("title", ""), "link": item.get("url", ""), "snippet": item.get("snippet", ""), "source_engine": "clearweb"} for item in raw]
            return {"status": "completed", "results": results, "count": len(results)}
        except ImportError:
            logger.warning("ARGUS clear-web enrichment is unavailable")
            return {"status": "degraded", "results": [], "error": "clear-web enrichment unavailable"}
        except Exception as exc:
            logger.exception("OSINT search failed")
            return {"status": "failed", "results": [], "error": str(exc)}

    def _scrape(self, urls: list[dict], max_workers: int) -> dict[str, Any]:
        """Scrape URLs via argus_engine/scrape.py."""
        try:
            from argus_engine.scrape import scrape_multiple

            results = scrape_multiple(urls, max_workers=max_workers)
            return {"results": results, "count": len(results)}
        except ImportError:
            logger.warning("argus_engine.scrape not available")
            return {"error": "argus_engine.scrape module not available"}
        except Exception as exc:
            logger.exception("OSINT scraping failed")
            return {"error": str(exc)}

    def _error_result(self, message: str) -> dict[str, Any]:
        return {
            "agent_name": self.name,
            "status": "failed",
            "error": message,
            "results": [],
            "scraped": {},
        }
