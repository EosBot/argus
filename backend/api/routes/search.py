"""OSINT search route — wraps argus_engine/search.py.

POST /api/search  → search dark web engines via Tor SOCKS proxy
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status

from backend.auth.rbac import require_permission
from backend.core.redis_client import redis_client

from backend.api.models.requests import SearchRequest
from backend.api.models.responses import SearchResponse, SearchResultItem

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/search", tags=["osint"])


@router.post("", response_model=SearchResponse)
async def search(req: SearchRequest, _user=Depends(require_permission("search:execute"))) -> SearchResponse:
    """Search dark web engines via Tor and return deduplicated results.

    Results are cached in Redis for 30 minutes to avoid redundant Tor requests.
    """
    # Check cache first
    cache_key = f"search:{req.query}"
    cached = await redis_client.get_json(cache_key)
    if cached is not None:
        return SearchResponse(
            query=req.query,
            results=[SearchResultItem(**r) for r in cached.get("results", [])],
            total=cached.get("total", 0),
            cached=True,
        )

    # Run the synchronous argus_engine search in a thread pool to avoid blocking
    try:
        from argus_engine.search import get_search_results

        loop = asyncio.get_event_loop()
        raw_results = await loop.run_in_executor(
            None,
            lambda: get_search_results(req.query, max_workers=req.max_workers),
        )
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Search module (argus_engine) not available",
        )
    except Exception as exc:
        logger.exception("Search failed for query=%r", req.query)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {exc}",
        ) from exc

    # Build response items
    items = [
        SearchResultItem(title=r.get("title", "Untitled"), link=r.get("link", ""))
        for r in raw_results
        if r.get("link")
    ]

    # Cache results (30 min TTL)
    await redis_client.set_json(
        cache_key,
        {"results": [item.model_dump() for item in items], "total": len(items)},
        ex=1800,
    )

    return SearchResponse(
        query=req.query,
        results=items,
        total=len(items),
        cached=False,
    )
