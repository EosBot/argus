"""Credential-free passive APIs routed through the configured Tor proxy."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from backend.core.config import settings

PUBLIC_API_EXECUTORS = {"wayback_machine"}
_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z",
    re.IGNORECASE,
)


def _public_url(value: str) -> str:
    target = value.strip()
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    if len(target) > 2_048 or any(ord(char) < 32 for char in target):
        raise ValueError("Wayback aceita uma URL pública de até 2048 caracteres")
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Wayback exige uma URL HTTP(S) pública sem credenciais")
    host = parsed.hostname.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global:
            raise ValueError("Wayback recusa endereços privados, locais ou reservados")
    except ValueError as exc:
        if "recusa" in str(exc):
            raise
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as unicode_exc:
            raise ValueError("Host inválido para Wayback") from unicode_exc
        if not _DOMAIN.fullmatch(host):
            raise ValueError("Wayback exige um domínio registrável ou IP público")
    return target


async def execute_public_api(tool_id: str, target: str) -> dict[str, Any]:
    if tool_id not in PUBLIC_API_EXECUTORS:
        raise KeyError(tool_id)
    clean_url = _public_url(target)
    timeout = httpx.Timeout(15.0, connect=10.0)
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        proxy=settings.tor_proxy,
    ) as client, client.stream(
        "GET",
        "https://archive.org/wayback/available",
        headers={"Accept": "application/json"},
        params={"url": clean_url},
    ) as response:
        if response.status_code >= 400:
            raise RuntimeError(f"Wayback respondeu HTTP {response.status_code}")
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > 1_000_000:
                raise RuntimeError("Wayback excedeu o limite de resposta de 1 MB")
            chunks.append(chunk)
    try:
        payload = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Wayback retornou JSON inválido") from exc
    closest = payload.get("archived_snapshots", {}).get("closest", {}) if isinstance(payload, dict) else {}
    snapshot_url = closest.get("url") if isinstance(closest, dict) else None
    if snapshot_url:
        snapshot_host = urlparse(str(snapshot_url)).hostname
        if snapshot_host not in {"web.archive.org", "web.archive.org."}:
            snapshot_url = None
    return {
        "query_url": clean_url,
        "available": bool(closest.get("available")) if isinstance(closest, dict) else False,
        "snapshot": {
            "url": snapshot_url,
            "timestamp": str(closest.get("timestamp", ""))[:32],
            "status": str(closest.get("status", ""))[:8],
        } if snapshot_url else None,
        "source": "Internet Archive Wayback Availability API",
        "transport": "tor",
    }
