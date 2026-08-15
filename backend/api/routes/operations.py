"""Operational configuration, tool catalog, live tasks and safe browsing."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.agents.registry import get_registry
from backend.auth.rbac import Role, has_permission, require_permission
from backend.core.database import get_db
from backend.core.redis_client import redis_client
from backend.core.secrets import decrypt_secret, encrypt_secret, mask_secret
from backend.db.models import AuditLog, Evidence, Investigation
from backend.features.research import redact_sensitive_payload
from backend.orchestrator.dispatcher import dispatcher
from backend.tools.connectors import CONNECTOR_EXECUTORS, execute_connector
from backend.tools.configuration import defaults_for, validate_parameters
from backend.tools.native import NATIVE_EXECUTORS, execute_native
from backend.tools.public_api import PUBLIC_API_EXECUTORS, execute_public_api
from backend.tools.registry import get_tool_registry
from backend.tools.system import SYSTEM_EXECUTORS, execute_system

router = APIRouter(prefix="/api/operations", tags=["operations"])
SETTINGS_KEY = "argus:settings"
_settings: dict[str, Any] = {
    "mode": "basic",
    "task_models": {},
    "tools": {},
    "opsec": {"level": "maximum", "torProxy": "socks5h://127.0.0.1:9050"},
    "interface": {"language": "pt-BR", "reducedMotion": False},
    "connections": [],
}

BINARY_TOOLS = {
    "nmap_scanner": "nmap", "nuclei_scanner": "nuclei", "subfinder": "subfinder",
    "ssl_analyzer": "sslyze", "technology_detector": "whatweb",
    "dns_resolver": "dnsrecon", "github_leak_scanner": "gitleaks",
}
CONNECTOR_TOOLS = {
    "shodan_query": "shodan", "censys_query": "censys",
    "virustotal_lookup": "virustotal", "abuseipdb_check": "abuseipdb", "otx_query": "otx",
    "threatfox_query": "threatfox", "urlhaus_query": "urlhaus",
}


async def _read_settings() -> dict[str, Any]:
    stored = await redis_client.get_json(SETTINGS_KEY)
    if not isinstance(stored, dict):
        return copy.deepcopy(_settings)
    merged = copy.deepcopy(_settings)
    for key, value in stored.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


class SettingsUpdate(BaseModel):
    mode: str | None = None
    task_models: dict[str, str] | None = None
    tools: dict[str, dict[str, Any]] | None = None
    opsec: dict[str, Any] | None = None
    interface: dict[str, Any] | None = None
    connections: list[dict[str, Any]] | None = None


@router.get("/settings")
async def get_settings(_user=Depends(require_permission("agents:invoke"))) -> dict[str, Any]:
    output = copy.deepcopy(await _read_settings())
    for connection in output.get("connections", []):
        connection["apiKey"] = mask_secret(connection.get("apiKey"))
    return output


@router.put("/settings")
async def update_settings(body: SettingsUpdate, _user=Depends(require_permission("users:manage"))) -> dict[str, Any]:
    current = await _read_settings()
    updates = body.model_dump(exclude_none=True)
    if "tools" in updates:
        validated_tools: dict[str, dict[str, Any]] = {}
        registry = get_tool_registry()
        for tool_id, tool_update in updates["tools"].items():
            if registry.get(tool_id) is None:
                raise HTTPException(400, f"Ferramenta desconhecida: {tool_id}")
            sanitized = dict(tool_update)
            if "parameters" in sanitized:
                try:
                    sanitized["parameters"] = validate_parameters(
                        tool_id, sanitized["parameters"]
                    )
                except (TypeError, ValueError) as exc:
                    raise HTTPException(400, str(exc)) from exc
            validated_tools[tool_id] = sanitized
        existing_tools = current.get("tools", {})
        updates["tools"] = {
            **existing_tools,
            **{
                tool_id: {**existing_tools.get(tool_id, {}), **tool_update}
                for tool_id, tool_update in validated_tools.items()
            },
        }
    if "connections" in updates:
        existing = {item.get("id"): item for item in current.get("connections", [])}
        secured = []
        for connection in updates["connections"]:
            key = connection.get("apiKey")
            if key and "***" in key:
                connection["apiKey"] = existing.get(connection.get("id"), {}).get("apiKey")
            else:
                connection["apiKey"] = encrypt_secret(key)
            secured.append(connection)
        updates["connections"] = secured
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(current.get(key), dict):
            current[key] = {**current[key], **value}
        else:
            current[key] = value
    _settings.clear()
    _settings.update(current)
    await redis_client.set_json(SETTINGS_KEY, current)
    output = copy.deepcopy(current)
    for connection in output.get("connections", []):
        connection["apiKey"] = mask_secret(connection.get("apiKey"))
    return output


@router.get("/tools")
async def list_tools(_user=Depends(require_permission("agents:invoke"))) -> dict[str, Any]:
    settings = await _read_settings()
    overrides = settings.get("tools", {})
    configured_connections = {item.get("type") for item in settings.get("connections", []) if item.get("apiKey")}
    items = []
    for item in get_tool_registry().list_tools():
        name = item["name"]
        binary = BINARY_TOOLS.get(name)
        connector = CONNECTOR_TOOLS.get(name)
        agent_backed = bool(item.get("agent_name"))
        if binary:
            installed = shutil.which(binary) is not None
            available = installed and agent_backed
            implementation = "binary+agent" if agent_backed else "binary_without_executor"
            availability = "available" if available else ("not_installed" if not installed else "not_implemented")
        elif connector:
            configured = connector in configured_connections
            implemented = agent_backed or name in CONNECTOR_EXECUTORS
            available = configured and implemented
            implementation = "connector+agent" if agent_backed else ("connector" if name in CONNECTOR_EXECUTORS else "connector_without_executor")
            availability = "available" if available else ("needs_connection" if implemented and not configured else "not_implemented")
        elif name in NATIVE_EXECUTORS:
            available, implementation = True, "native"
            availability = "available"
        elif name in SYSTEM_EXECUTORS:
            binary = SYSTEM_EXECUTORS[name]
            installed = shutil.which(binary) is not None
            available, implementation = installed, "system"
            availability = "available" if installed else "not_installed"
        elif name in PUBLIC_API_EXECUTORS:
            available, implementation, availability = True, "public_api", "available"
        elif agent_backed:
            available, implementation = True, "agent"
            availability = "available"
        else:
            available, implementation = False, "catalog_only"
            availability = "not_implemented"
        override = overrides.get(name, {})
        parameters = {**defaults_for(name), **override.get("parameters", {})}
        items.append({
            "id": name,
            "name": name.replace("_", " ").title(),
            "category": item["category"],
            "description": item["description"],
            "capabilities": item["capabilities"],
            "enabled": override.get("enabled", available),
            "configured": available or bool(parameters),
            "availability": availability,
            "implementation": implementation,
            "binary": binary,
            "connector": connector,
            "agent_name": item.get("agent_name"),
            "requiresApiKey": item["cost"] != "free",
            "parameters": parameters,
        })
    return {"items": items, "total": len(items)}


class ToolExecuteRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=100_000)
    investigation_id: str | None = None
    authorized: bool = False
    parameters: dict[str, Any] = Field(default_factory=dict)


@router.post("/tools/{tool_id}/execute")
async def execute_tool(
    tool_id: str,
    body: ToolExecuteRequest,
    user=Depends(require_permission("agents:invoke")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool = get_tool_registry().get(tool_id)
    if tool is None:
        raise HTTPException(404, "Ferramenta não registrada")
    if not body.investigation_id:
        raise HTTPException(400, "Vincule a execução a uma investigação para preservar auditoria e evidência")
    native = tool_id in NATIVE_EXECUTORS
    system = tool_id in SYSTEM_EXECUTORS
    public_api = tool_id in PUBLIC_API_EXECUTORS
    connector_type = CONNECTOR_EXECUTORS.get(tool_id)
    if not tool.agent_name and not native and not system and not public_api and not connector_type:
        raise HTTPException(409, "Esta integração ainda não possui executor; configure um conector ou pacote compatível")
    required_binary = BINARY_TOOLS.get(tool_id) or SYSTEM_EXECUTORS.get(tool_id)
    if required_binary and shutil.which(required_binary) is None:
        raise HTTPException(409, f"Dependência indisponível no runtime: {required_binary}")
    active_action = tool.agent_name == "infrastructure_mapper"
    if active_action:
        if not has_permission(Role(user.role), "pentest:execute"):
            raise HTTPException(403, "Seu perfil não permite ações ativas")
        if not body.authorized:
            raise HTTPException(403, "Ferramentas de infraestrutura exigem autorização explícita")
    if body.investigation_id:
        investigation = await db.scalar(select(Investigation).where(Investigation.id == body.investigation_id))
        if investigation is None:
            raise HTTPException(404, "Investigação não encontrada")
        if user.role != "admin" and investigation.owner_id != user.sub:
            raise HTTPException(403, "Esta investigação pertence a outro usuário")

    if connector_type:
        settings = await _read_settings()
        connection = next(
            (item for item in settings.get("connections", []) if item.get("type") == connector_type and item.get("apiKey")),
            None,
        )
        if connection is None:
            raise HTTPException(409, f"Configure uma conexão {connector_type} antes de executar")
        api_key = decrypt_secret(connection.get("apiKey"))
        if not api_key:
            raise HTTPException(409, f"A conexão {connector_type} não possui chave válida")
        try:
            connector_result = await execute_connector(tool_id, body.target, api_key)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except (RuntimeError, httpx.HTTPError) as exc:
            raise HTTPException(502, str(exc)) from exc
        safe_result, redaction_count = redact_sensitive_payload(connector_result)
        redacted = json.dumps(safe_result, ensure_ascii=False, sort_keys=True, default=str)
        task_id = hashlib.sha256(
            f"{user.sub}:{tool_id}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:12]
        if body.investigation_id:
            db.add(Evidence(
                investigation_id=body.investigation_id,
                type="connector_result",
                content=redacted,
                content_hash=hashlib.sha256(redacted.encode()).hexdigest(),
                metadata_={"tool_id": tool_id, "connector": connector_type, "task_id": task_id, "operator_id": user.sub, "redaction_count": redaction_count},
            ))
        db.add(AuditLog(
            user_id=user.sub,
            action="tool.execute",
            resource_type="investigation" if body.investigation_id else "tool",
            resource_id=body.investigation_id or tool_id,
            details={"tool_id": tool_id, "implementation": "connector", "connector": connector_type, "task_id": task_id, "redaction_count": redaction_count},
        ))
        await db.commit()
        return {"task_id": task_id, "tool_id": tool_id, "implementation": "connector", "status": "completed", "result": safe_result}

    if public_api:
        try:
            public_result = await execute_public_api(tool_id, body.target)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except (RuntimeError, httpx.HTTPError) as exc:
            raise HTTPException(502, str(exc)) from exc
        safe_result, redaction_count = redact_sensitive_payload(public_result)
        task_id = hashlib.sha256(
            f"{user.sub}:{tool_id}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:12]
        serialized = json.dumps(safe_result, ensure_ascii=False, sort_keys=True)
        db.add(Evidence(
            investigation_id=body.investigation_id,
            type="public_api_result",
            content=serialized,
            content_hash=hashlib.sha256(serialized.encode()).hexdigest(),
            metadata_={"tool_id": tool_id, "task_id": task_id, "operator_id": user.sub, "transport": "tor", "redaction_count": redaction_count},
        ))
        db.add(AuditLog(
            user_id=user.sub,
            action="tool.execute",
            resource_type="investigation",
            resource_id=body.investigation_id,
            details={"tool_id": tool_id, "implementation": "public_api", "task_id": task_id, "transport": "tor", "redaction_count": redaction_count},
        ))
        await db.commit()
        return {"task_id": task_id, "tool_id": tool_id, "implementation": "public_api", "status": "completed", "result": safe_result}

    if native:
        try:
            native_result = execute_native(tool_id, body.target)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        task_id = hashlib.sha256(
            f"{user.sub}:{tool_id}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:12]
        if body.investigation_id:
            serialized = json.dumps(native_result, ensure_ascii=False, sort_keys=True)
            db.add(Evidence(
                investigation_id=body.investigation_id,
                type="native_tool_result",
                content=serialized,
                content_hash=hashlib.sha256(serialized.encode()).hexdigest(),
                metadata_={"tool_id": tool_id, "task_id": task_id, "operator_id": user.sub},
            ))
        db.add(AuditLog(
            user_id=user.sub,
            action="tool.execute",
            resource_type="investigation" if body.investigation_id else "tool",
            resource_id=body.investigation_id or tool_id,
            details={"tool_id": tool_id, "implementation": "native", "task_id": task_id},
        ))
        await db.commit()
        return {"task_id": task_id, "tool_id": tool_id, "implementation": "native", "status": "completed", "result": native_result}

    if system:
        try:
            system_result = await execute_system(tool_id, body.target)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(502, str(exc)) from exc
        safe_result, redaction_count = redact_sensitive_payload(system_result)
        task_id = hashlib.sha256(
            f"{user.sub}:{tool_id}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:12]
        serialized = json.dumps(safe_result, ensure_ascii=False, sort_keys=True)
        db.add(Evidence(
            investigation_id=body.investigation_id,
            type="system_tool_result",
            content=serialized,
            content_hash=hashlib.sha256(serialized.encode()).hexdigest(),
            metadata_={"tool_id": tool_id, "task_id": task_id, "operator_id": user.sub, "redaction_count": redaction_count},
        ))
        db.add(AuditLog(
            user_id=user.sub,
            action="tool.execute",
            resource_type="investigation",
            resource_id=body.investigation_id,
            details={"tool_id": tool_id, "implementation": "system", "task_id": task_id, "redaction_count": redaction_count},
        ))
        await db.commit()
        return {"task_id": task_id, "tool_id": tool_id, "implementation": "system", "status": "completed", "result": safe_result}

    settings = await _read_settings()
    configured_parameters = settings.get("tools", {}).get(tool_id, {}).get("parameters", {})
    if not isinstance(configured_parameters, dict):
        configured_parameters = {}
    context: dict[str, Any] = {
        **defaults_for(tool_id),
        **configured_parameters,
        **body.parameters,
        "investigation_id": body.investigation_id,
        "authorized": body.authorized,
        "operator_id": user.sub,
    }
    if tool.agent_name == "infrastructure_mapper":
        option_keys = set(defaults_for(tool_id)) | set(configured_parameters) | set(body.parameters)
        context.update({
            "target": body.target,
            "tools": [BINARY_TOOLS.get(tool_id, tool_id)],
            "options": {key: context[key] for key in option_keys if key in context},
        })
    elif tool.agent_name == "crypto_tracer":
        context.update({
            "address": body.target.strip(),
            "chain": "btc" if tool_id == "btc_tracer" else "eth",
        })
    elif tool.agent_name == "forensic_analyst":
        context.update({
            "text": body.target,
            "geolocate": tool_id == "ip_geolocator",
            "discover_subdomains": tool_id == "subdomain_discoverer",
        })
    elif tool.agent_name in {"threat_intel_analyst", "report_writer"}:
        context["text"] = body.target
    else:
        context.update({"query": body.target, "target": body.target})
    dispatched = await dispatcher.dispatch(tool.agent_name, body.target, context)
    db.add(AuditLog(
        user_id=user.sub,
        action="tool.execute",
        resource_type="investigation" if body.investigation_id else "tool",
        resource_id=body.investigation_id or tool_id,
        details={
            "tool_id": tool_id,
            "agent_name": tool.agent_name,
            "task_id": dispatched.task_id,
            "authorized": body.authorized,
            "target": body.target[:500],
        },
    ))
    await db.commit()
    return {"task_id": dispatched.task_id, "tool_id": tool_id, "agent_name": tool.agent_name, "status": dispatched.status}


@router.get("/agents/status")
async def agent_status(user=Depends(require_permission("agents:invoke"))) -> dict[str, Any]:
    dispatches = []
    for key in await redis_client.keys("dispatch:*"):
        data = await redis_client.get_json(key)
        if data and (user.role == "admin" or data.get("owner_id") == user.sub):
            dispatches.append(data)
    latest = {item.get("agent_name"): item for item in dispatches}
    items = []
    for agent in get_registry().list_agents():
        task = latest.get(agent["name"])
        items.append({
            **agent,
            "status": task.get("status", "ready") if task else "ready",
            "task_id": task.get("task_id") if task else None,
            "error": task.get("error") if task else None,
            "updated_at": task.get("completed_at") or task.get("dispatched_at") if task else None,
        })
    return {"items": items}


class BrowseRequest(BaseModel):
    url: str = Field(..., min_length=8)
    investigation_id: str | None = None


class ConnectionTestRequest(BaseModel):
    id: str | None = None
    type: str
    endpoint: str
    apiKey: str | None = None


@router.post("/connections/test")
async def test_connection(body: ConnectionTestRequest, _user=Depends(require_permission("users:manage"))) -> dict[str, Any]:
    parsed = urlparse(body.endpoint)
    allowed_hosts = {
        "shodan": {"api.shodan.io"},
        "virustotal": {"www.virustotal.com", "virustotal.com"},
        "censys": {"search.censys.io", "api.platform.censys.io"},
        "abuseipdb": {"api.abuseipdb.com"},
        "otx": {"otx.alienvault.com"},
        "threatfox": {"threatfox-api.abuse.ch"},
        "urlhaus": {"urlhaus-api.abuse.ch"},
    }
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts.get(body.type, set()):
        raise HTTPException(400, "Endpoint não permitido para este tipo de conexão")
    api_key = body.apiKey
    if body.id and (not api_key or "***" in api_key):
        stored = next((item for item in (await _read_settings()).get("connections", []) if item.get("id") == body.id), None)
        api_key = decrypt_secret(stored.get("apiKey")) if stored else None
    if body.type == "virustotal":
        headers = {"x-apikey": api_key or ""}
    elif body.type == "abuseipdb":
        headers = {"Key": api_key or "", "Accept": "application/json"}
    elif body.type == "otx":
        headers = {"X-OTX-API-KEY": api_key or ""}
    elif body.type in {"threatfox", "urlhaus"}:
        headers = {"Auth-Key": api_key or "", "Accept": "application/json"}
    else:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            if body.type == "threatfox":
                response = await client.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    headers=headers,
                    json={"query": "types"},
                )
            elif body.type == "urlhaus":
                response = await client.get(
                    "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1/",
                    headers=headers,
                )
            else:
                response = await client.get(body.endpoint, headers=headers)
        return {"ok": 200 <= response.status_code < 400, "status_code": response.status_code}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": str(exc)}


@router.post("/browser/navigate")
async def browse(
    body: BrowseRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("agents:invoke")),
) -> dict[str, Any]:
    parsed = urlparse(body.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(400, "Use uma URL HTTP(S) válida")
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", parsed.hostname.lower()):
        raise HTTPException(400, "Use um endereço Tor v3 .onion válido (56 caracteres)")
    result = await get_registry().invoke_agent("dark_web_crawler", {
        "query": parsed.hostname,
        "browse_url": body.url,
        "investigation_id": body.investigation_id,
    })
    capture = result.get("browse", {})
    evidence_id = None
    if body.investigation_id:
        investigation = await db.scalar(select(Investigation).where(Investigation.id == body.investigation_id))
        if investigation is None:
            raise HTTPException(404, "Investigação não encontrada")
        if user.role != "admin" and investigation.owner_id != user.sub:
            raise HTTPException(403, "Esta investigação pertence a outro usuário")
        captured_at = datetime.now(timezone.utc).isoformat()
        previous_hash = await db.scalar(
            select(Evidence.content_hash)
            .where(Evidence.investigation_id == body.investigation_id)
            .order_by(Evidence.created_at.desc())
            .limit(1)
        ) or ("0" * 64)
        content_hash = str(capture.get("content_hash") or hashlib.sha256(str(capture.get("content") or "").encode()).hexdigest())
        chain_hash = hashlib.sha256(f"{previous_hash}:{content_hash}:{captured_at}".encode()).hexdigest()
        evidence = Evidence(
            investigation_id=body.investigation_id,
            type="browser_capture",
            source_url=str(capture.get("url") or body.url),
            content=str(capture.get("content") or ""),
            content_hash=content_hash,
            metadata_={
                "title": capture.get("title", ""),
                "http_status": capture.get("status"),
                "elapsed_ms": capture.get("elapsed_ms"),
                "content_type": capture.get("content_type", ""),
                "isolation": capture.get("isolation", {}),
                "operator_id": user.sub,
                "captured_at": captured_at,
                "previous_hash": previous_hash,
                "chain_hash": chain_hash,
            },
        )
        db.add(evidence)
        await db.flush()
        evidence_id = evidence.id
        db.add(AuditLog(
            user_id=user.sub,
            action="browser.capture",
            resource_type="evidence",
            resource_id=evidence.id,
            details={"investigation_id": body.investigation_id, "url": evidence.source_url, "content_hash": content_hash, "chain_hash": chain_hash},
        ))
    return {"url": body.url, "investigation_id": body.investigation_id, "evidence_id": evidence_id, "result": capture, "status": result.get("status")}


@router.get("/browser/history")
async def browser_history(
    limit: int = 25,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("agents:invoke")),
) -> dict[str, Any]:
    query = (
        select(Evidence, Investigation)
        .join(Investigation, Evidence.investigation_id == Investigation.id)
        .where(Evidence.type == "browser_capture")
        .order_by(Evidence.created_at.desc())
        .limit(max(1, min(limit, 100)))
    )
    if user.role != "admin":
        query = query.where(Investigation.owner_id == user.sub)
    rows = (await db.execute(query)).all()
    return {"items": [{
        "id": evidence.id,
        "investigation_id": investigation.id,
        "investigation_title": investigation.title,
        "url": evidence.source_url,
        "content_hash": evidence.content_hash,
        "created_at": evidence.created_at,
        "metadata": evidence.metadata_ or {},
    } for evidence, investigation in rows]}
