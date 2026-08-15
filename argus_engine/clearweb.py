"""Clear-web enrichment used by the ARGUS OSINT agent."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ClearwebSearch:
    """Small adapter around the maintained DDGS client."""

    def __init__(self) -> None:
        self._search_fn: Any = None
        try:
            from ddgs import DDGS  # type: ignore[import-untyped]

            def search(query: str, max_results: int = 5) -> list[dict[str, str]]:
                with DDGS() as client:
                    return [
                        {
                            "title": result.get("title", ""),
                            "url": result.get("href", ""),
                            "snippet": result.get("body", ""),
                        }
                        for result in client.text(query, max_results=max_results)
                    ]

            self._search_fn = search
        except ImportError:
            logger.warning("DDGS is unavailable; clear-web enrichment is disabled")

    def is_available(self) -> bool:
        return self._search_fn is not None

    def search(self, query: str, max_results: int = 5) -> list[dict[str, str]]:
        if not query.strip():
            raise ValueError("A consulta não pode ser vazia")
        if not 1 <= max_results <= 100:
            raise ValueError("max_results deve estar entre 1 e 100")
        if self._search_fn is None:
            return []
        try:
            return self._search_fn(query.strip(), max_results=max_results)
        except Exception as exc:
            logger.warning("Clear-web search failed: %s", exc)
            return []
