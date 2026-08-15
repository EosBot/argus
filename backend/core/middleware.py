"""ASGI middleware — rate limiting and security headers.

Adapts the existing argus_engine/security/rate_limiter.py sliding window logic
and argus_engine/security/middleware.py security headers for use as FastAPI/Starlette
ASGI middleware.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Any, ClassVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from backend.core.config import settings

logger = logging.getLogger(__name__)


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding window rate limiter.

    Adapted from argus_engine/security/rate_limiter.py for ASGI use.
    """

    def __init__(self, default_max: int = 100, default_window: int = 60) -> None:
        self._default_max = default_max
        self._default_window = default_window
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, key: str, max_requests: int | None = None, window: int | None = None) -> tuple[bool, int]:
        """Check if request is allowed. Returns (allowed, remaining)."""
        max_req = max_requests or self._default_max
        win = window or self._default_window
        now = time.monotonic()
        window_start = now - win

        with self._lock:
            timestamps = self._requests[key]
            # Remove expired
            active = [t for t in timestamps if t > window_start]
            self._requests[key] = active

            if len(active) >= max_req:
                return False, 0

            active.append(now)
            remaining = max_req - len(active)
            return True, remaining


class RateLimitMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that enforces rate limits per client IP.

    Returns 429 Too Many Requests when limit is exceeded.
    Adds X-RateLimit-* headers to responses.
    """

    def __init__(self, app: Any, max_requests: int | None = None, window: int | None = None) -> None:
        super().__init__(app)
        self._limiter = SlidingWindowRateLimiter(
            default_max=max_requests or settings.rate_limit_default_max,
            default_window=window or settings.rate_limit_default_window,
        )

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        """Process request with rate limiting."""
        if request.method == "OPTIONS" or request.url.path in {"/health", "/ready"}:
            return await call_next(request)
        rate_key = self._get_rate_key(request)
        allowed, remaining = self._limiter.is_allowed(rate_key)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={
                    "X-RateLimit-Limit": str(settings.rate_limit_default_max),
                    "X-RateLimit-Remaining": "0",
                    "Retry-After": str(settings.rate_limit_default_window),
                },
            )

        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_default_max)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract client IP from request, respecting X-Forwarded-For."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    @classmethod
    def _get_rate_key(cls, request: Request) -> str:
        """Isolate authenticated sessions without retaining bearer credentials."""
        client_ip = cls._get_client_ip(request)
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            fingerprint = hashlib.sha256(authorization.encode()).hexdigest()[:20]
            return f"{client_ip}:token:{fingerprint}"
        return f"{client_ip}:anonymous"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that adds security headers to all responses.

    Adapted from argus_engine/security/middleware.py.
    """

    SECURITY_HEADERS: ClassVar[dict[str, str]] = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera()",
        "X-XSS-Protection": "1; mode=block",
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        """Add security headers to response."""
        response = await call_next(request)
        for header, value in self.SECURITY_HEADERS.items():
            response.headers[header] = value
        return response
