"""Allowlisted passive OSINT API connectors with bounded responses."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from urllib.parse import quote, urlparse

import httpx

MAX_RESPONSE_BYTES = 1_000_000
CONNECTOR_EXECUTORS = {
    "shodan_query": "shodan",
    "censys_query": "censys",
    "virustotal_lookup": "virustotal",
    "abuseipdb_check": "abuseipdb",
    "otx_query": "otx",
    "threatfox_query": "threatfox",
    "urlhaus_query": "urlhaus",
}


def _clean_target(value: str, maximum: int = 2_000) -> str:
    target = value.strip()
    if not target or len(target) > maximum or any(ord(char) < 32 for char in target):
        raise ValueError("Alvo inválido para consulta")
    return target


def _global_ip(value: str) -> str:
    address = ipaddress.ip_address(_clean_target(value, 64))
    if not address.is_global:
        raise ValueError("A consulta exige um endereço IP público global")
    return str(address)


async def _request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    data: dict[str, str] | None = None,
) -> dict[str, Any]:
    timeout = httpx.Timeout(12.0, connect=8.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        async with client.stream(
            method, url, headers=headers, params=params, json=json_body, data=data
        ) as response:
            if response.status_code >= 400:
                raise RuntimeError(f"Conector respondeu HTTP {response.status_code}")
            content_type = response.headers.get("content-type", "").lower()
            if "json" not in content_type:
                raise RuntimeError("Conector retornou conteúdo não JSON")
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise RuntimeError("Resposta do conector excedeu 1 MB")
                chunks.append(chunk)
    try:
        parsed = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Conector retornou JSON inválido") from exc
    return parsed if isinstance(parsed, dict) else {"data": parsed}


def _otx_type(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
        return "IPv4" if address.version == 4 else "IPv6"
    except ValueError:
        pass
    if re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        return "file"
    if re.fullmatch(r"[A-Fa-f0-9]{40}", value):
        return "file"
    if re.fullmatch(r"[A-Fa-f0-9]{32}", value):
        return "file"
    if value.startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", value):
        return "domain"
    raise ValueError("OTX aceita IP, domínio, URL ou hash MD5/SHA-1/SHA-256")


async def execute_connector(tool_id: str, target: str, api_key: str) -> dict[str, Any]:
    """Execute one known passive lookup; no caller-provided endpoint is used."""
    if not api_key:
        raise ValueError("Chave do conector não configurada")
    target = _clean_target(target)

    if tool_id == "shodan_query":
        try:
            ip = _global_ip(target)
        except ValueError:
            return await _request_json(
                "GET", "https://api.shodan.io/shodan/host/search",
                headers={"Accept": "application/json"}, params={"key": api_key, "query": target, "minify": "true"},
            )
        return await _request_json(
            "GET", f"https://api.shodan.io/shodan/host/{quote(ip, safe='')}",
            headers={"Accept": "application/json"}, params={"key": api_key, "minify": "true"},
        )
    if tool_id == "censys_query":
        ip = _global_ip(target)
        return await _request_json(
            "GET", f"https://api.platform.censys.io/v3/global/asset/host/{quote(ip, safe='')}",
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/vnd.censys.api.v3.host.v1+json"},
        )
    if tool_id == "virustotal_lookup":
        return await _request_json(
            "GET", "https://www.virustotal.com/api/v3/search",
            headers={"x-apikey": api_key, "Accept": "application/json"}, params={"query": target, "limit": 10},
        )
    if tool_id == "abuseipdb_check":
        ip = _global_ip(target)
        return await _request_json(
            "GET", "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"}, params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        )
    if tool_id == "otx_query":
        indicator_type = _otx_type(target)
        return await _request_json(
            "GET", f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{quote(target, safe='')}/general",
            headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"},
        )
    if tool_id == "threatfox_query":
        return await _request_json(
            "POST", "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": api_key, "Accept": "application/json"},
            json_body={"query": "search_ioc", "search_term": target, "exact_match": True},
        )
    if tool_id == "urlhaus_query":
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or len(target) > 2_048:
            raise ValueError("URLhaus exige uma URL HTTP(S) válida")
        return await _request_json(
            "POST", "https://urlhaus-api.abuse.ch/v1/url/",
            headers={"Auth-Key": api_key, "Accept": "application/json"},
            data={"url": target},
        )
    raise KeyError(tool_id)
