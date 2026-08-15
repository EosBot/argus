"""Redis pub/sub for real-time event streaming.

Provides typed channels for findings, agent status updates, and
correlation alerts. Supports both publish-only and subscribe patterns
with async message handlers.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

from backend.core.redis_client import redis_client

logger = logging.getLogger(__name__)


class PubSubChannel:
    """Pub/sub channel name constants."""

    FINDINGS_NEW = "findings.new"
    AGENT_STATUS = "agent.status"
    CORRELATION_ALERT = "correlation.alert"

    ALL: frozenset[str] = frozenset({
        FINDINGS_NEW,
        AGENT_STATUS,
        CORRELATION_ALERT,
    })


# Type alias for async message handlers.
MessageHandler = Callable[[str, dict[str, Any]], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class PubSubMessage:
    """A message received from a pub/sub channel.

    Attributes:
        channel: Channel name the message was received on.
        data: Deserialized message payload.
        timestamp: ISO 8601 receive timestamp.
        raw: Original raw string payload.
    """

    channel: str
    data: dict[str, Any]
    timestamp: str = ""
    raw: str = ""


@dataclass
class _Subscription:
    """Internal subscription state."""

    channel: str
    handler: MessageHandler
    active: bool = True


class RedisPubSub:
    """Async Redis pub/sub client with typed channels.

    Publishes JSON-serialized messages to channels and registers
    async handlers for incoming messages. Gracefully degrades when
    Redis is unavailable (messages are logged but not lost).

    Usage::

        pubsub = RedisPubSub()
        await pubsub.publish(PubSubChannel.FINDINGS_NEW, {"finding_id": "abc"})

        async def on_finding(channel: str, data: dict) -> None:
            print(f"New finding: {data}")

        await pubsub.subscribe(PubSubChannel.FINDINGS_NEW, on_finding)
    """

    def __init__(self) -> None:
        self._subscriptions: dict[str, list[_Subscription]] = {}
        self._pubsub = None

    async def publish(
        self,
        channel: str,
        data: dict[str, Any],
    ) -> bool:
        """Publish a JSON-serialized message to a channel.

        Args:
            channel: Target channel name.
            data: Message payload (must be JSON-serializable).

        Returns:
            True if published successfully, False otherwise.
        """
        if channel not in PubSubChannel.ALL:
            logger.warning("unknown pub/sub channel: %s", channel)

        envelope = {
            "data": data,
            "published_at": datetime.now(timezone.utc).isoformat(),
            "channel": channel,
        }

        if not redis_client.is_connected:
            logger.debug(
                "Redis unavailable — message to %s logged but not published: %s",
                channel,
                envelope,
            )
            return False

        try:
            await redis_client.publish_json(channel, envelope)
            return True
        except Exception as exc:
            logger.warning("Failed to publish to %s: %s", channel, exc)
            return False

    async def publish_finding(
        self,
        finding_id: str,
        investigation_id: str,
        title: str,
        severity: str = "info",
        source: str = "",
        data: dict[str, Any] | None = None,
    ) -> bool:
        """Publish a new finding event.

        Convenience wrapper around :meth:`publish` for findings.

        Args:
            finding_id: Unique finding identifier.
            investigation_id: Associated investigation.
            title: Finding title.
            severity: Severity level (info, low, medium, high, critical).
            source: Source agent or tool name.
            data: Additional finding data.

        Returns:
            True if published successfully.
        """
        return await self.publish(
            PubSubChannel.FINDINGS_NEW,
            {
                "finding_id": finding_id,
                "investigation_id": investigation_id,
                "title": title,
                "severity": severity,
                "source": source,
                "data": data or {},
            },
        )

    async def publish_agent_status(
        self,
        agent_name: str,
        status: str,
        investigation_id: str = "",
        details: dict[str, Any] | None = None,
    ) -> bool:
        """Publish an agent status update.

        Args:
            agent_name: Agent identifier.
            status: Status string (running, completed, failed, idle).
            investigation_id: Associated investigation (if any).
            details: Additional status details.

        Returns:
            True if published successfully.
        """
        return await self.publish(
            PubSubChannel.AGENT_STATUS,
            {
                "agent_name": agent_name,
                "status": status,
                "investigation_id": investigation_id,
                "details": details or {},
            },
        )

    async def publish_correlation_alert(
        self,
        investigation_id: str,
        correlation_type: str,
        description: str,
        confidence: float = 0.5,
        entities: list[str] | None = None,
    ) -> bool:
        """Publish a correlation alert.

        Args:
            investigation_id: Associated investigation.
            correlation_type: Type of correlation detected.
            description: Human-readable description.
            confidence: Confidence score (0.0 - 1.0).
            entities: Related entity values.

        Returns:
            True if published successfully.
        """
        return await self.publish(
            PubSubChannel.CORRELATION_ALERT,
            {
                "investigation_id": investigation_id,
                "correlation_type": correlation_type,
                "description": description,
                "confidence": confidence,
                "entities": entities or [],
            },
        )

    async def subscribe(
        self,
        channel: str,
        handler: MessageHandler,
    ) -> None:
        """Register an async handler for a channel.

        The handler receives ``(channel, data)`` and must be awaitable.

        Args:
            channel: Channel to subscribe to.
            handler: Async callback for incoming messages.
        """
        sub = _Subscription(channel=channel, handler=handler)
        self._subscriptions.setdefault(channel, []).append(sub)

        if redis_client.is_connected and self._pubsub is None:
            self._pubsub = redis_client._client.pubsub()

        logger.info("Subscribed handler to channel: %s", channel)

    async def unsubscribe(
        self,
        channel: str,
        handler: MessageHandler | None = None,
    ) -> None:
        """Remove a handler from a channel.

        If ``handler`` is None, all handlers for the channel are removed.
        """
        if channel not in self._subscriptions:
            return
        if handler is None:
            del self._subscriptions[channel]
        else:
            self._subscriptions[channel] = [
                s for s in self._subscriptions[channel] if s.handler is not handler
            ]

    async def dispatch(self, channel: str, raw: str) -> None:
        """Dispatch a raw message to registered handlers.

        Deserializes the JSON payload and calls all handlers for the channel.

        Args:
            channel: Channel the message arrived on.
            raw: Raw JSON string payload.
        """
        try:
            envelope = json.loads(raw)
            data = envelope.get("data", envelope)
        except json.JSONDecodeError:
            logger.warning("Invalid JSON on channel %s: %s", channel, raw)
            return

        handlers = self._subscriptions.get(channel, [])
        for sub in handlers:
            if not sub.active:
                continue
            try:
                await sub.handler(channel, data)
            except Exception as exc:
                logger.exception(
                    "Handler error on channel %s: %s", channel, exc
                )

    async def listen(self, channel: str) -> None:
        """Listen for messages on a channel (blocking).

        This method blocks indefinitely, dispatching incoming messages
        to registered handlers. Run as a background task.

        Args:
            channel: Channel to listen on.
        """
        if not redis_client.is_connected:
            logger.warning("Cannot listen — Redis not connected")
            return

        if self._pubsub is None:
            self._pubsub = redis_client._client.pubsub()

        await self._pubsub.subscribe(channel)
        logger.info("Listening on channel: %s", channel)

        try:
            async for message in self._pubsub.listen():
                if message["type"] == "message":
                    await self.dispatch(
                        message["channel"], message["data"]
                    )
        except Exception as exc:
            logger.exception("Listen error on %s: %s", channel, exc)
        finally:
            await self._pubsub.unsubscribe(channel)


# Singleton instance
redis_pubsub = RedisPubSub()
