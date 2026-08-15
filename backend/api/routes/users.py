"""Database-backed administrative user management."""

from __future__ import annotations

import secrets
import string

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routes.auth import _hash_password
from backend.auth.rbac import Role, require_permission
from backend.core.database import get_db
from backend.db.models import AuditLog, User

router = APIRouter(prefix="/api/users", tags=["users"])


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    role: Role = Role.INVESTIGATOR


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)


def _view(user: User) -> dict:
    return {"id": user.id, "username": user.username, "email": user.email, "role": user.role.value if isinstance(user.role, Role) else str(user.role), "is_active": user.is_active, "created_at": user.created_at}


@router.get("")
async def list_users(db: AsyncSession = Depends(get_db), _admin=Depends(require_permission("users:manage"))) -> dict:
    users = (await db.scalars(select(User).order_by(User.username))).all()
    return {"items": [_view(user) for user in users]}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_user(body: UserCreate, db: AsyncSession = Depends(get_db), admin=Depends(require_permission("users:manage"))) -> dict:
    if await db.scalar(select(User.id).where((User.username == body.username) | (User.email == body.email))):
        raise HTTPException(409, "Username ou e-mail já cadastrado")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    temporary_password = "".join(secrets.choice(alphabet) for _ in range(20))
    user = User(username=body.username, email=str(body.email), hashed_password=_hash_password(temporary_password), role=body.role, is_active=True)
    db.add(user)
    await db.flush()
    db.add(AuditLog(user_id=admin.sub, action="user.create", resource_type="user", resource_id=user.id, details={"username": user.username, "role": body.role.value}))
    return {**_view(user), "temporary_password": temporary_password}


@router.patch("/{user_id}")
async def update_user(user_id: str, body: UserUpdate, db: AsyncSession = Depends(get_db), admin=Depends(require_permission("users:manage"))) -> dict:
    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(404, "Usuário não encontrado")
    changes = body.model_dump(exclude_none=True)
    password = changes.pop("password", None)
    for key, value in changes.items():
        setattr(user, key, value)
    if password:
        user.hashed_password = _hash_password(password)
    db.add(AuditLog(user_id=admin.sub, action="user.update", resource_type="user", resource_id=user.id, details={"fields": sorted(body.model_fields_set)}))
    await db.flush()
    return _view(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: str, db: AsyncSession = Depends(get_db), admin=Depends(require_permission("users:manage"))) -> None:
    if user_id == admin.sub:
        raise HTTPException(400, "Você não pode excluir a própria conta")
    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(404, "Usuário não encontrado")
    user_role = user.role.value if isinstance(user.role, Role) else str(user.role)
    if user_role == Role.ADMIN.value:
        admin_count = await db.scalar(select(func.count()).select_from(User).where(User.role == Role.ADMIN))
        if (admin_count or 0) <= 1:
            raise HTTPException(409, "O último administrador não pode ser excluído")
    db.add(AuditLog(user_id=admin.sub, action="user.delete", resource_type="user", resource_id=user.id, details={"username": user.username, "role": user_role}))
    await db.delete(user)
