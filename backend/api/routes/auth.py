"""Authentication routes — login, refresh, user info.

POST /api/auth/login    → issue JWT token pair
POST /api/auth/refresh  → exchange refresh token for new access token
GET  /api/auth/me       → current user info
"""

from __future__ import annotations

import logging
import json
import os
import secrets
import string
from pathlib import Path

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.jwt import (
    TokenError,
    create_access_token,
    create_token_pair,
    decode_token,
)
from backend.auth.rbac import Role, require_permission
from backend.core.config import settings
from backend.core.database import AsyncSessionLocal, get_db
from backend.db.models import User

from backend.api.models.requests import LoginRequest, RefreshRequest
from backend.api.models.responses import TokenResponse, UserInfoResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Password hashing (bcrypt directly — passlib 1.7.4 is incompatible with bcrypt >= 4.1)
def _hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

async def ensure_bootstrap_admin() -> None:
    """Create the first database admin once and store its random password as 0600."""
    credentials_path = Path(__file__).resolve().parents[3] / "argus" / "setup" / ".admin_credentials.json"
    async with AsyncSessionLocal() as db:
        if (await db.scalar(select(func.count(User.id)))) or 0:
            return
        credentials: dict[str, str] = {}
        if credentials_path.exists():
            try:
                credentials = json.loads(credentials_path.read_text())
            except (OSError, ValueError):
                credentials = {}
        username = credentials.get("username") or os.environ.get("ARGUS_ADMIN_USER", "admin")
        password = credentials.get("password") or os.environ.get("ARGUS_ADMIN_PASSWORD")
        if not password:
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
            password = "".join(secrets.choice(alphabet) for _ in range(24))
            credentials_path.parent.mkdir(parents=True, exist_ok=True)
            credentials_path.write_text(json.dumps({"username": username, "password": password}, indent=2))
            os.chmod(credentials_path, 0o600)
        db.add(User(username=username, email=os.environ.get("ARGUS_ADMIN_EMAIL", "admin@argus.local"), hashed_password=_hash_password(password), role=Role.ADMIN, is_active=True))
        await db.commit()
        logger.warning("Bootstrap admin created; credentials are stored at %s", credentials_path)


async def _authenticate(db: AsyncSession, username: str, password: str) -> User | None:
    """Validate credentials against PostgreSQL."""
    user = await db.scalar(select(User).where(User.username == username))
    if user is None:
        return None
    if not _verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    return user


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    """Authenticate and issue a JWT token pair."""
    user = await _authenticate(db, req.username, req.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    tokens = create_token_pair(
        subject=user.id,
        role=user.role.value if isinstance(user.role, Role) else str(user.role),
        extra_claims={"username": user.username},
    )
    return TokenResponse(**tokens)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(req: RefreshRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    """Exchange a refresh token for a new access token."""
    try:
        token_data = decode_token(req.refresh_token)
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    if token_data.token_type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type: refresh token required",
        )
    user = await db.scalar(select(User).where(User.id == token_data.sub, User.is_active.is_(True)))
    if user is None:
        raise HTTPException(status_code=401, detail="User is inactive or no longer exists")

    new_access = create_access_token(
        subject=token_data.sub,
        role=token_data.role,
        extra_claims={k: v for k, v in token_data.extra.items()},
    )
    return TokenResponse(
        access_token=new_access,
        refresh_token=req.refresh_token,
        token_type="bearer",
    )


@router.get("/me", response_model=UserInfoResponse)
async def get_current_user(
    token_data=Depends(require_permission("investigations:read")),
    db: AsyncSession = Depends(get_db),
) -> UserInfoResponse:
    """Return the current authenticated user's info."""
    user = await db.scalar(select(User).where(User.id == token_data.sub))
    if user:
        return UserInfoResponse(id=user.id, username=user.username, email=user.email, role=user.role.value if isinstance(user.role, Role) else str(user.role), is_active=user.is_active, created_at=user.created_at)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="User not found",
    )
