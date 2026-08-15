"""Small encrypted-at-rest codec for provider and connector credentials."""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from backend.core.config import settings

_PREFIX = "enc:v1:"
_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(settings.jwt_secret_key.encode()).digest()))


def encrypt_secret(value: str | None) -> str | None:
    if not value or value.startswith(_PREFIX):
        return value
    return _PREFIX + _fernet.encrypt(value.encode()).decode()


def decrypt_secret(value: str | None) -> str | None:
    if not value or not value.startswith(_PREFIX):
        return value
    try:
        return _fernet.decrypt(value.removeprefix(_PREFIX).encode()).decode()
    except InvalidToken:
        return None


def mask_secret(value: str | None) -> str | None:
    plain = decrypt_secret(value)
    if not plain:
        return None
    return "***" if len(plain) <= 4 else f"{plain[:3]}***{plain[-4:]}"
