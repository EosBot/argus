"""Web scraping route — wraps argus_engine/scrape.py.

POST /api/scrape  → scrape multiple URLs (Tor for .onion, direct for clearweb)
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, status

from backend.auth.rbac import require_permission
from backend.core.redis_client import redis_client

from backend.api.models.requests import ScrapeRequest
from backend.api.models.responses import ScrapeResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scrape", tags=["osint"])


@router.post("", response_model=ScrapeResponse)
async def scrape(req: ScrapeRequest, _user=Depends(require_permission("scrape:execute"))) -> ScrapeResponse:
    """Scrape multiple URLs concurrently.

    .onion URLs are routed through Tor SOCKS proxy automatically.
    Results are cached in Redis for 30 minutes.
    """
    # Build cache key from sorted URLs
    urls_data = [{"link": u.link, "title": u.title} for u in req.urls]
    cache_key = f"scrape:{hash(tuple(u['link'] for u in urls_data))}"

    # Check cache
    cached = await redis_client.get_json(cache_key)
    if cached is not None:
        return ScrapeResponse(results=cached, total=len(cached), cached=True)

    # Run synchronous scrape in thread pool
    try:
        from argus_engine.scrape import scrape_multiple

        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None,
            lambda: scrape_multiple(urls_data, max_workers=req.max_workers),
        )
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scrape module (argus_engine) not available",
        )
    except Exception as exc:
        logger.exception("Scrape failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scrape failed: {exc}",
        ) from exc

    # Cache results (30 min TTL)
    await redis_client.set_json(cache_key, results, ex=1800)

    return ScrapeResponse(results=results, total=len(results), cached=False)
