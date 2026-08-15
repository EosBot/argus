"""Redis async client wrapper.

Wraps aioredis to provide a simple async interface for caching,
pub/sub, and rate-limit state. Compatible with the CacheClient protocol
defined in argus.cache.result_cache.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import redis.asyncio as redis

from backend.core.config import settings

logger = logging.getLogger(__name__)


class RedisClient:
    """Async Redis client with JSON serialization and pub/sub support."""

    def __init__(self) -> None:
        self._pool: redis.ConnectionPool | None = None
        self._client: redis.Redis | None = None

    async def connect(self) -> None:
        """Initialize the connection pool."""
        self._pool = redis.ConnectionPool.from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=20,
        )
        self._client = redis.Redis(connection_pool=self._pool)
        # Verify connectivity
        await self._client.ping()
        logger.info("Redis connected: %s:%s", settings.redis_host, settings.redis_port)

    async def disconnect(self) -> None:
        """Close the connection pool."""
        if self._pool is not None:
            await self._pool.disconnect()
            self._pool = None
            self._client = None
            logger.info("Redis disconnected")

    @property
    def is_connected(self) -> bool:
        return self._client is not None

    async def ping(self) -> bool:
        """Return whether Redis answers a live PING request."""
        if self._client is None:
            return False
        try:
            return bool(await self._client.ping())
        except Exception:
            return False

    # -- Key-value operations --------------------------------------------------

    async def get(self, key: str) -> str | None:
        """Get a raw string value by key."""
        if self._client is None:
            return None
        return await self._client.get(key)

    async def set(
        self,
        key: str,
        value: str,
        ex: int | None = None,
    ) -> None:
        """Set a raw string value with optional TTL (seconds)."""
        if self._client is None:
            return
        await self._client.set(key, value, ex=ex)

    async def delete(self, key: str) -> None:
        """Delete a key."""
        if self._client is None:
            return
        await self._client.delete(key)

    async def exists(self, key: str) -> bool:
        """Check if a key exists."""
        if self._client is None:
            return False
        return bool(await self._client.exists(key))

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching a glob-style pattern.

        Args:
            pattern: Glob pattern (e.g. ``"collection:*"``).

        Returns:
            List of matching keys. Empty list if Redis is not connected.
        """
        if self._client is None:
            return []
        return list(await self._client.keys(pattern))

    # -- JSON helpers ----------------------------------------------------------

    async def get_json(self, key: str) -> Any | None:
        """Get and JSON-deserialize a value."""
        raw = await self.get(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    async def set_json(
        self,
        key: str,
        value: Any,
        ex: int | None = None,
    ) -> None:
        """JSON-serialize and store a value."""
        await self.set(key, json.dumps(value, default=str), ex=ex)

    # -- Pub/Sub ---------------------------------------------------------------

    async def publish(self, channel: str, message: str) -> None:
        """Publish a message to a channel."""
        if self._client is None:
            return
        await self._client.publish(channel, message)

    async def publish_json(self, channel: str, data: Any) -> None:
        """Publish a JSON-serialized message to a channel."""
        await self.publish(channel, json.dumps(data, default=str))


# Singleton instance
redis_client = RedisClient()
