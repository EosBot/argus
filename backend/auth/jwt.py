"""JWT token creation and validation.

Uses python-jose for JWT signing/verification with HS256.
Supports access tokens (short-lived) and refresh tokens (long-lived).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt

from backend.core.config import settings

logger = logging.getLogger(__name__)


class TokenData:
    """Decoded token payload."""

    def __init__(
        self,
        sub: str,
        role: str,
        exp: datetime,
        iat: datetime,
        token_type: str = "access",
        **extra: Any,
    ) -> None:
        self.sub = sub
        self.role = role
        self.exp = exp
        self.iat = iat
        self.token_type = token_type
        self.extra = extra

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.exp


def create_access_token(
    subject: str,
    role: str,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Create a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)

    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "exp": expire,
        "iat": now,
        "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(subject: str, role: str) -> str:
    """Create a long-lived JWT refresh token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.jwt_refresh_token_expire_days)

    payload = {
        "sub": subject,
        "role": role,
        "exp": expire,
        "iat": now,
        "type": "refresh",
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_token_pair(
    subject: str,
    role: str,
    extra_claims: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Create both access and refresh tokens."""
    return {
        "access_token": create_access_token(subject, role, extra_claims),
        "refresh_token": create_refresh_token(subject, role),
        "token_type": "bearer",
    }


def decode_token(token: str) -> TokenData:
    """Decode and validate a JWT token.

    Raises:
        TokenError: If the token is invalid, expired, or malformed.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as exc:
        raise TokenError(f"Invalid token: {exc}") from exc

    sub = payload.get("sub")
    role = payload.get("role")
    exp = payload.get("exp")
    iat = payload.get("iat")

    if not sub or not role:
        raise TokenError("Token missing required claims (sub, role)")

    return TokenData(
        sub=str(sub),
        role=str(role),
        exp=datetime.fromtimestamp(exp, tz=timezone.utc),
        iat=datetime.fromtimestamp(iat, tz=timezone.utc) if iat else datetime.now(timezone.utc),
        token_type=payload.get("type", "access"),
        **{k: v for k, v in payload.items() if k not in ("sub", "role", "exp", "iat", "type")},
    )


class TokenError(Exception):
    """Raised when a token is invalid or expired."""
    pass
