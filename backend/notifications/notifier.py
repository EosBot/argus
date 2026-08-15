"""Notification service — create, persist, and publish notifications.

Provides NotificationService with:
- notify(user_id, title, body, severity) — persist + publish to Redis
- get_notifications(user_id, unread_only) — query from PostgreSQL
- mark_as_read(notification_id) — mark a notification as read

Redis channels:
- notification:user:{user_id} — per-user notifications
- notification:system — broadcast to all connected clients
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update

from backend.core.database import AsyncSessionLocal
from backend.core.redis_client import redis_client
from backend.db.models import Notification

logger = logging.getLogger(__name__)

# Redis channel templates
USER_CHANNEL = "notification:user:{user_id}"
SYSTEM_CHANNEL = "notification:system"


@dataclass(frozen=True, slots=True)
class NotificationPayload:
    """A notification ready for WebSocket delivery.

    Attributes:
        id: Notification UUID.
        user_id: Target user (None for system-wide).
        title: Short notification title.
        body: Optional detailed message.
        severity: Severity level (info, low, medium, high, critical).
        created_at: ISO 8601 creation timestamp.
    """

    id: str
    user_id: str | None
    title: str
    body: str | None
    severity: str
    created_at: str


@dataclass
class NotifyResult:
    """Result of a notify() call.

    Attributes:
        notification_id: The created notification ID.
        persisted: Whether the database write succeeded.
        published: Whether the Redis publish succeeded.
        channel: The Redis channel used.
        errors: List of error messages encountered.
    """

    notification_id: str
    persisted: bool = False
    published: bool = False
    channel: str = ""
    errors: list[str] = field(default_factory=list)


class NotificationService:
    """Create and deliver notifications via PostgreSQL + Redis pub/sub."""

    async def notify(
        self,
        title: str,
        body: str | None = None,
        severity: str = "info",
        user_id: str | None = None,
    ) -> NotifyResult:
        """Create a notification, persist it, and publish to Redis.

        Args:
            title: Short notification title.
            body: Optional detailed message.
            severity: Severity level (info, low, medium, high, critical).
            user_id: Target user ID (None for system-wide notifications).

        Returns:
            NotifyResult with persistence and publish status.
        """
        notification_id = ""
        persisted = False
        published = False
        errors: list[str] = []

        # -- Persist to PostgreSQL -------------------------------------------
        try:
            async with AsyncSessionLocal() as session:
                notification = Notification(
                    user_id=user_id,
                    title=title,
                    body=body,
                    severity=severity,
                )
                session.add(notification)
                await session.flush()
                notification_id = notification.id
                await session.commit()
                persisted = True
        except Exception as exc:
            logger.exception("Failed to persist notification")
            errors.append(f"persistence error: {exc}")
            # Continue to publish even if persistence fails — the
            # WebSocket subscribers should still see the notification.

        # -- Build payload ---------------------------------------------------
        payload = NotificationPayload(
            id=notification_id,
            user_id=user_id,
            title=title,
            body=body,
            severity=severity,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        # -- Publish to Redis -----------------------------------------------
        channel = USER_CHANNEL.format(user_id=user_id) if user_id else SYSTEM_CHANNEL
        if not redis_client.is_connected:
            logger.debug("Redis unavailable — notification not published")
            errors.append("Redis not connected")
            return NotifyResult(
                notification_id=notification_id,
                persisted=persisted,
                published=False,
                channel=channel,
                errors=errors,
            )

        try:
            await redis_client.publish_json(channel, {
                "type": "notification",
                "data": {
                    "id": payload.id,
                    "user_id": payload.user_id,
                    "title": payload.title,
                    "body": payload.body,
                    "severity": payload.severity,
                    "created_at": payload.created_at,
                },
            })
            published = True
        except Exception as exc:
            logger.warning("Failed to publish notification: %s", exc)
            errors.append(f"publish error: {exc}")

        return NotifyResult(
            notification_id=notification_id,
            persisted=persisted,
            published=published,
            channel=channel,
            errors=errors,
        )

    async def get_notifications(
        self,
        user_id: str | None = None,
        unread_only: bool = False,
        limit: int = 50,
    ) -> list[NotificationPayload]:
        """Query notifications from PostgreSQL.

        Args:
            user_id: Filter by user (None for system-wide notifications).
            unread_only: If True, only return unread notifications.
            limit: Maximum results to return.

        Returns:
            List of NotificationPayload, newest first.
        """
        try:
            async with AsyncSessionLocal() as session:
                stmt = select(Notification)
                if user_id is not None:
                    stmt = stmt.where(Notification.user_id == user_id)
                if unread_only:
                    stmt = stmt.where(Notification.read.is_(False))
                stmt = stmt.order_by(Notification.created_at.desc()).limit(limit)

                result = await session.execute(stmt)
                rows = result.scalars().all()

                return [
                    NotificationPayload(
                        id=row.id,
                        user_id=row.user_id,
                        title=row.title,
                        body=row.body,
                        severity=row.severity,
                        created_at=row.created_at.isoformat() if row.created_at else "",
                    )
                    for row in rows
                ]
        except Exception as exc:
            logger.exception("Failed to query notifications")
            return []

    async def mark_as_read(self, notification_id: str) -> bool:
        """Mark a notification as read.

        Args:
            notification_id: The notification UUID.

        Returns:
            True if the update succeeded.
        """
        try:
            async with AsyncSessionLocal() as session:
                await session.execute(
                    update(Notification)
                    .where(Notification.id == notification_id)
                    .values(read=True)
                )
                await session.commit()
                return True
        except Exception as exc:
            logger.exception("Failed to mark notification as read")
            return False


# Singleton instance
notification_service = NotificationService()
