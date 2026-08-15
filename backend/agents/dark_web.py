"""DarkWebCrawler agent — dark web search + scraping via Tor SOCKS5.

Wraps argus_engine/search.py (9 onion search engines), argus_engine/scrape.py (web scraping),
and argus_engine/browser/safe_browser.py (Playwright + Tor).
"""

from __future__ import annotations

import asyncio
import logging
import time
import re
from typing import Any

from backend.agents.base import BaseAgent

logger = logging.getLogger(__name__)


class DarkWebCrawler(BaseAgent):
    """Dark web investigation agent.

    Searches onion engines, scrapes results, and browses dark web sites
    via Tor SOCKS5 proxy. All sync argus_engine code runs in thread pool.
    """

    name = "dark_web_crawler"
    description = "Dark web search and crawling via Tor — searches onion engines, scrapes results, browses .onion sites"
    capabilities = [
        "dark_web_search",
        "onion_scraping",
        "tor_browsing",
        "search_engine_query",
    ]

    async def run(self, task: dict[str, Any]) -> dict[str, Any]:
        """Execute dark web investigation.

        Task dict keys:
            - query (str): Search term (required)
            - max_workers (int): Concurrent search threads (default: 5)
            - scrape_results (bool): Whether to scrape found URLs (default: false)
            - max_scrape (int): Max URLs to scrape (default: 5)
            - browse_url (str): Specific .onion URL to browse

        Returns:
            dict with keys: query, results (list), scraped (dict), browse (dict)
        """
        start = time.monotonic()
        query = task.get("query", "")
        if not query:
            return self._error_result("Missing required 'query' parameter")

        max_workers = task.get("max_workers", 5)
        scrape_results = task.get("scrape_results", False)
        max_scrape = task.get("max_scrape", 5)
        browse_url = task.get("browse_url", "")

        result: dict[str, Any] = {
            "agent_name": self.name,
            "query": query,
            "results": [],
            "scraped": {},
            "browse": {},
        }

        loop = asyncio.get_event_loop()

        # Step 1: Search dark web engines
        expanded_queries = self._expand_queries(query) if task.get("expand_queries", True) else [query]
        search_data = await loop.run_in_executor(
            None, self._search_dark_web, expanded_queries, max_workers
        )
        result["results"] = search_data.get("results", [])
        result["search_status"] = search_data.get("status", "unknown")
        result["queries"] = expanded_queries
        result["source_engines"] = sorted({item.get("source_engine", "unknown") for item in result["results"]})

        # Step 2: Scrape top results if requested
        if scrape_results and result["results"]:
            urls_to_scrape = result["results"][:max_scrape]
            scraped = await loop.run_in_executor(
                None, self._scrape_urls, urls_to_scrape, max_workers
            )
            result["scraped"] = scraped

        # Step 3: Browse specific URL if provided
        if browse_url:
            browse_data = await loop.run_in_executor(
                None, self._browse_url, browse_url
            )
            result["browse"] = browse_data

        elapsed = (time.monotonic() - start) * 1000
        result["execution_time_ms"] = round(elapsed, 2)
        result["status"] = "completed"
        return result

    @staticmethod
    def _expand_queries(query: str) -> list[str]:
        """Generate a small multilingual query set without inventing evidence."""
        clean = " ".join(query.split())
        variants = [clean]
        lowered = clean.lower()
        expansions = {
            "vazamento": ["data leak", "breach", "dump"],
            "credenciais": ["credentials", "credential exposure"],
            "cartório": ["cartorio", "registro civil"],
            "banco de dados": ["database exposure", "database dump"],
        }
        for trigger, terms in expansions.items():
            if trigger in lowered:
                variants.extend(f"{clean} {term}" for term in terms)
        quoted_tokens = [token for token in re.findall(r"[\w.-]+", clean) if "." in token or "@" in token]
        variants.extend(f'"{token}"' for token in quoted_tokens[:2])
        return list(dict.fromkeys(variants))[:4]

    def _search_dark_web(self, queries: list[str], max_workers: int) -> dict[str, Any]:
        """Search dark web engines via argus_engine/search.py."""
        try:
            from argus_engine.search import get_search_results

            results: list[dict[str, Any]] = []
            seen: set[str] = set()
            for query in queries:
                for item in get_search_results(query, max_workers=max_workers):
                    link = str(item.get("link", ""))
                    if not link or link in seen:
                        continue
                    seen.add(link)
                    results.append({**item, "matched_query": query})
            return {"status": "completed", "results": results, "count": len(results)}
        except ImportError:
            logger.warning("argus_engine.search not available")
            return {"status": "degraded", "results": [], "error": "argus_engine.search module not available"}
        except Exception as exc:
            logger.exception("Dark web search failed")
            return {"status": "failed", "results": [], "error": str(exc)}

    def _scrape_urls(self, urls: list[dict], max_workers: int) -> dict[str, Any]:
        """Scrape URLs via argus_engine/scrape.py."""
        try:
            from argus_engine.scrape import scrape_multiple

            results = scrape_multiple(urls, max_workers=max_workers)
            return {"results": results, "count": len(results)}
        except ImportError:
            logger.warning("argus_engine.scrape not available")
            return {"error": "argus_engine.scrape module not available"}
        except Exception as exc:
            logger.exception("URL scraping failed")
            return {"error": str(exc)}

    def _browse_url(self, url: str) -> dict[str, Any]:
        """Browse a URL via argus_engine/browser/safe_browser.py."""
        try:
            from argus_engine.browser.safe_browser import SafeBrowser

            with SafeBrowser() as browser:
                return browser.navigate(url)
        except ImportError:
            logger.warning("argus_engine.browser.safe_browser not available")
            return {"error": "SafeBrowser not available (Playwright required)"}
        except RuntimeError as exc:
            logger.warning("SafeBrowser init failed: %s", exc)
            return {"error": str(exc)}
        except Exception as exc:
            logger.exception("Browser navigation failed")
            return {"error": str(exc)}

    def _error_result(self, message: str) -> dict[str, Any]:
        return {
            "agent_name": self.name,
            "status": "failed",
            "error": message,
            "results": [],
            "scraped": {},
            "browse": {},
        }
