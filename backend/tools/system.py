"""Bounded passive executors backed by allowlisted runtime binaries."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
from typing import Any

SYSTEM_EXECUTORS = {"whois_lookup": "whois"}
_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z",
    re.IGNORECASE,
)
_SAFE_FIELDS = {
    "domain name": "domain_name",
    "registry domain id": "registry_domain_id",
    "registrar": "registrar",
    "registrar iana id": "registrar_iana_id",
    "creation date": "created_at",
    "created": "created_at",
    "updated date": "updated_at",
    "last updated": "updated_at",
    "registry expiry date": "expires_at",
    "expiration date": "expires_at",
    "status": "status",
    "domain status": "status",
    "name server": "name_servers",
    "nserver": "name_servers",
    "dnssec": "dnssec",
    "netrange": "network_range",
    "cidr": "cidr",
    "netname": "network_name",
    "country": "country",
}


def _whois_target(value: str) -> str:
    target = value.strip().rstrip(".").lower()
    try:
        address = ipaddress.ip_address(target)
        if not address.is_global:
            raise ValueError("WHOIS aceita somente IP público ou domínio registrável")
        return str(address)
    except ValueError as exc:
        if "somente" in str(exc):
            raise
    try:
        ascii_domain = target.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domínio inválido para WHOIS") from exc
    if not _DOMAIN.fullmatch(ascii_domain):
        raise ValueError("WHOIS aceita somente IP público ou domínio registrável")
    return ascii_domain


def _parse_whois(target: str, output: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for raw_line in output.splitlines()[:10_000]:
        if ":" not in raw_line:
            continue
        raw_key, raw_value = raw_line.split(":", 1)
        key = _SAFE_FIELDS.get(raw_key.strip().lower())
        value = raw_value.strip()[:2_000]
        if not key or not value:
            continue
        if key in {"status", "name_servers"}:
            values = fields.setdefault(key, [])
            if value not in values and len(values) < 100:
                values.append(value)
        elif key not in fields:
            fields[key] = value
    return {
        "target": target,
        "fields": fields,
        "raw_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "privacy_filter": "registrant contact fields omitted",
    }


async def execute_system(tool_id: str, target: str) -> dict[str, Any]:
    """Execute one fixed passive binary with no shell and bounded output."""
    binary = SYSTEM_EXECUTORS.get(tool_id)
    if binary is None:
        raise KeyError(tool_id)
    clean_target = _whois_target(target)
    process = await asyncio.create_subprocess_exec(
        binary,
        clean_target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=20)
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.communicate()
        raise RuntimeError("WHOIS excedeu o limite de 20 segundos") from exc
    if len(stdout) + len(stderr) > 1_000_000:
        raise RuntimeError("WHOIS excedeu o limite de saída de 1 MB")
    if process.returncode not in {0, 1}:
        raise RuntimeError(f"WHOIS encerrou com código {process.returncode}")
    output = stdout.decode("utf-8", errors="replace")
    if not output.strip():
        raise RuntimeError("WHOIS não retornou dados")
    return _parse_whois(clean_target, output)
