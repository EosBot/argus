"""
ARGUS 2.0 — Backend FastAPI
==========================
Entrada unificada do sistema:
   - WebSocket  /ws/v1/terminal   → terminal interativo (streaming de tokens)
   - SSE        /sse/llm          → Server-Sent Events para o LLM
   - REST       /api/...          → endpoints OSINT, auth, investigations
   - Health     /health           → health check

Integração com LiteLLM via `litellm.acompletion` (async, OpenAI-format).
O gateway LiteLLM (config/litellm_config.yaml) expõe a mesma API OpenAI
em http://localhost:4000 — basta apontar LITELLM_BASE_URL para ele.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import litellm
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, text

from backend.core.config import settings
from backend.auth.jwt import TokenError, decode_token
from backend.core.database import AsyncSessionLocal, close_db, engine, init_db
from backend.core.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from backend.core.neo4j_client import neo4j_client
from backend.core.prompts import TERMINAL_SYSTEM_PROMPT
from backend.core.redis_client import redis_client
from backend.features.research import run_terminal_research
from backend.notifications.notifier import SYSTEM_CHANNEL, USER_CHANNEL
from backend.api.routes.exports import router as exports_router
from backend.db.models import AuditLog, Evidence, Investigation

# --- Pesquisa OSINT (terminal WS) ---
_RESEARCH_KEYWORDS = frozenset([
    "pesquis", "busc", "search", "investig", "data leak", "breach",
    "vazamento", "lookup", "find", "scan", "osint", "threat", "malware",
    "credential", "senha", "password", "exploit", "ioc", "dark web",
    "onion", "forum", "panel", "login", "dump", "leak", "cartório",
    "registro civil", "cpf", "cnpj",
])


def _is_research_query(text: str) -> bool:
    t = text.lower()
    return any(k in t for k in _RESEARCH_KEYWORDS)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("argus.backend")

# ---------------------------------------------------------------------------
# LiteLLM configuration
# ---------------------------------------------------------------------------
litellm.api_base = settings.litellm_base_url
litellm.drop_params = True


# ---------------------------------------------------------------------------
# Schemas REST (legacy — kept for backward compatibility)
# ---------------------------------------------------------------------------
class ChatRequest(BaseModel):
    """Payload de uma chamada de chat ao LLM via LiteLLM."""

    messages: list[dict[str, str]] = Field(
        ..., description="Lista de mensagens no formato OpenAI: [{'role': ..., 'content': ...}]"
    )
    model: str | None = Field(default=None, description="Modelo LiteLLM (default: LITELLM_MODEL)")
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, ge=1, le=32768)
    stream: bool = Field(default=False, description="Se true, retorna resposta em streaming")


class ChatResponse(BaseModel):
    model: str
    content: str
    usage: dict[str, Any] | None = None


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    litellm_base_url: str
    model: str


# ---------------------------------------------------------------------------
# Helpers LiteLLM
# ---------------------------------------------------------------------------
def _resolve_model(model: str | None) -> str:
    return model or settings.litellm_model


def _effective_content(message: Any) -> str:
    """Extrai conteúdo efetivo de uma mensagem/delta do litellm.

    Modelos de reasoning (DeepSeek R1, LongCat, Anthropic thinking, etc.)
    devolvem a resposta em ``reasoning_content`` quando ``content`` vem vazio.
    O objeto ``litellm.Message`` e os deltas de streaming carregam ambos os
    campos — o fallback segue a documentação oficial do litellm.
    """
    if message is None:
        return ""
    content = getattr(message, "content", None)
    if content:
        return content
    reasoning = getattr(message, "reasoning_content", None)
    if reasoning and reasoning != " ":
        return reasoning
    return ""


async def _llm_completion(
    req: ChatRequest,
    api_base: str | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Chamada assíncrona única ao LiteLLM (sem streaming).

    Args:
        req: pedido de chat.
        api_base: URL base do provider (sobrescreve o gateway LiteLLM).
        api_key: chave de API do provider (enviada como Bearer).
    """
    kwargs: dict[str, Any] = dict(
        model=_resolve_model(req.model),
        messages=req.messages,
        temperature=req.temperature if req.temperature is not None else settings.litellm_temperature,
        max_tokens=req.max_tokens or settings.litellm_max_tokens,
    )
    if api_base:
        kwargs["api_base"] = api_base
    if api_key:
        kwargs["api_key"] = api_key
    response = await litellm.acompletion(**kwargs)
    choice = response.choices[0]
    return {
        "model": response.model or _resolve_model(req.model),
        "content": _effective_content(choice.message),
        "usage": response.usage.model_dump() if response.usage else None,
    }


async def _llm_stream(
    req: ChatRequest,
    api_base: str | None = None,
    api_key: str | None = None,
) -> AsyncGenerator[str, None]:
    """Streaming de tokens do LiteLLM em formato SSE (`data: {...}\\n\\n`).

    Args:
        req: pedido de chat.
        api_base: URL base do provider (sobrescreve o gateway LiteLLM).
        api_key: chave de API do provider.
    """
    try:
        kwargs: dict[str, Any] = dict(
            model=_resolve_model(req.model),
            messages=req.messages,
            temperature=req.temperature if req.temperature is not None else settings.litellm_temperature,
            max_tokens=req.max_tokens or settings.litellm_max_tokens,
            stream=True,
        )
        if api_base:
            kwargs["api_base"] = api_base
        if api_key:
            kwargs["api_key"] = api_key
        stream = await litellm.acompletion(**kwargs)
        async for chunk in stream:
            delta = chunk.choices[0].delta
            token = _effective_content(delta)
            if token:
                payload = json.dumps({"type": "token", "content": token})
                yield f"data: {payload}\n\n"
        yield "data: {\"type\": \"done\"}\n\n"
    except Exception as exc:  # noqa: BLE001 — erro vira evento SSE, não quebra o stream
        logger.exception("Erro no streaming LiteLLM")
        payload = json.dumps({"type": "error", "message": str(exc)})
        yield f"data: {payload}\n\n"


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    logger.info(
        "ARGUS backend iniciando — LiteLLM em %s (modelo: %s)",
        settings.litellm_base_url,
        settings.litellm_model,
    )

    # Connect to Redis
    try:
        await redis_client.connect()
    except Exception as exc:
        logger.warning("Redis connection failed (continuing without cache): %s", exc)

    # Connect to Neo4j
    try:
        await neo4j_client.connect()
        await neo4j_client.create_constraints()
    except Exception as exc:
        logger.warning("Neo4j connection failed (continuing without graph): %s", exc)

    # Initialize database tables (dev convenience)
    try:
        await init_db()
        from backend.api.routes.auth import ensure_bootstrap_admin
        await ensure_bootstrap_admin()
    except Exception as exc:
        logger.warning("Database init failed (continuing without DB): %s", exc)

    logger.info("ARGUS backend pronto")
    yield
    logger.info("ARGUS backend encerrando...")

    # Cleanup
    await redis_client.disconnect()
    await neo4j_client.disconnect()
    await close_db()
    logger.info("ARGUS backend encerrado")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="ARGUS 2.0 Backend",
    version=settings.app_version,
    description="Entrada unificada: WebSocket terminal, SSE LLM, REST OSINT, auth, investigations.",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Rate limiting + security headers (ASGI middleware)
# ---------------------------------------------------------------------------
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

# CORS must wrap rate-limit responses so browsers can read HTTP 429 details.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# JWT Auth middleware (attaches user to request state)
# ---------------------------------------------------------------------------
from backend.auth.middleware import JWTAuthMiddleware

app.add_middleware(JWTAuthMiddleware)

# ---------------------------------------------------------------------------
# API Routers
# ---------------------------------------------------------------------------
from backend.api.routes.audit import router as audit_router
from backend.api.routes.auth import router as auth_router
from backend.api.routes.users import router as users_router
from backend.api.routes.search import router as search_router
from backend.api.routes.scrape import router as scrape_router
from backend.api.routes.pentest import router as pentest_router
from backend.api.routes.agents import router as agents_router
from backend.api.routes.investigations import router as investigations_router
from backend.api.routes.iocs import router as iocs_router
from backend.api.routes.threats import router as threats_router
from backend.api.routes.monitoring import router as monitoring_router
from backend.api.routes.providers import router as providers_router
from backend.api.routes.collections import router as collections_router
from backend.api.routes.exploitations import router as exploitations_router
from backend.api.routes.operations import router as operations_router
from backend.orchestrator.integration import router as orchestrator_router
from backend.orchestrator.integration import ws_router as orchestrator_ws_router
from backend.export.taxii.server import (
    taxii_discovery, api_root_info, list_collections,
    get_collection, get_manifest, get_objects, add_objects,
)
from backend.api.routes.audit import security_audit

# Workaround for FastAPI 0.141.1 include_router bug: add routes directly
app.add_api_route("/taxii2/", taxii_discovery, methods=["GET"], name="taxii_discovery")
app.add_api_route("/taxii2/api1/", api_root_info, methods=["GET"], name="api_root_info")
app.add_api_route("/taxii2/api1/collections/", list_collections, methods=["GET"], name="list_collections")
app.add_api_route("/taxii2/api1/collections/{collection_id}/", get_collection, methods=["GET"], name="get_collection")
app.add_api_route("/taxii2/api1/collections/{collection_id}/manifest/", get_manifest, methods=["GET"], name="get_manifest")
app.add_api_route("/taxii2/api1/collections/{collection_id}/objects/", get_objects, methods=["GET"], name="get_objects")
app.add_api_route("/taxii2/api1/collections/{collection_id}/objects/", add_objects, methods=["POST"], name="add_objects")
app.add_api_route("/api/audit/security", security_audit, methods=["GET"], name="security_audit")
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(search_router)
app.include_router(scrape_router)
app.include_router(pentest_router)
app.include_router(agents_router)
app.include_router(investigations_router)
app.include_router(iocs_router)
app.include_router(threats_router)
app.include_router(monitoring_router)
app.include_router(providers_router)
app.include_router(collections_router)
app.include_router(exploitations_router)
app.include_router(operations_router)
app.include_router(exports_router)
app.include_router(orchestrator_router)
app.include_router(orchestrator_ws_router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    """Process liveness only; use ``/ready`` for dependency readiness."""
    return HealthResponse(
        status="ok",
        service="argus-backend",
        version=settings.app_version,
        litellm_base_url=settings.litellm_base_url,
        model=settings.litellm_model,
    )


@app.get("/ready", tags=["system"])
async def readiness() -> JSONResponse:
    """Report readiness only when all required persistence services answer."""
    checks = {
        "postgres": False,
        "redis": await redis_client.ping(),
        "neo4j": await neo4j_client.verify_connectivity(),
    }
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        checks["postgres"] = True
    except Exception:
        logger.exception("PostgreSQL readiness check failed")

    ready = all(checks.values())
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ready" if ready else "unavailable", "checks": checks},
    )


# ---------------------------------------------------------------------------
# REST endpoints (legacy — kept for backward compatibility)
# ---------------------------------------------------------------------------
@app.get("/", tags=["system"])
async def root() -> dict[str, str]:
    return {"service": "ARGUS 2.0 Backend", "docs": "/docs", "health": "/health"}


@app.post("/api/chat", response_model=ChatResponse, tags=["llm"])
async def chat(req: ChatRequest) -> ChatResponse:
    """Chamada única ao LLM via LiteLLM."""
    _, api_base, api_key = await _resolve_rest_model(req)
    result = await _llm_completion(req, api_base=api_base, api_key=api_key)
    return ChatResponse(**result)


@app.post("/api/chat/stream", tags=["llm"])
async def chat_stream(req: ChatRequest) -> StreamingResponse:
    """Chamada ao LLM com resposta em streaming (SSE)."""
    _, api_base, api_key = await _resolve_rest_model(req)
    return StreamingResponse(
        _llm_stream(req, api_base=api_base, api_key=api_key),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/models", tags=["llm"])
async def list_models() -> dict[str, list[str]]:
    """Lista os modelos disponíveis no gateway LiteLLM."""
    try:
        models = await litellm.acompletion(
            model=_resolve_model(None),
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
        )
        return {"models": [models.model or settings.litellm_model]}
    except Exception:  # noqa: BLE001 — gateway indisponível não derruba o endpoint
        return {"models": [settings.litellm_model]}


# ---------------------------------------------------------------------------
# WebSocket — terminal interativo
# ---------------------------------------------------------------------------
async def _resolve_terminal_model(payload_model: str | None) -> tuple[str, str | None, str | None]:
    """Resolve o modelo e credenciais para o terminal WS.

    Ordem de resolução:
      1. Se payload.model existe e != "auto" → usa ele (api_base/key = None).
      2. Senão, lê provider ativo do store (Redis): se active.model definido →
         usa o modelo + endpoint + apiKey completos do provider.
      3. Se NENHUM provider ativo existe → levanta RuntimeError com mensagem clara.

    NUNCA cai em settings.litellm_model nem em AutoRouter: o AutoRouter opera
    sobre um catálogo estático que inclui modelos locais (ollama) — o terminal
    só roda com o provider que o investigador configurou explicitamente.

    Retorna (modelo, api_base, api_key). A apiKey é a COMPLETA do store,
    nunca a mascarada.
    """
    from backend.api.routes.providers import _load_store

    # 1. Modelo explícito no payload (diferente de "auto")
    if payload_model and payload_model != "auto":
        return payload_model, None, None

    # 2. Provider ativo do store
    store = await _load_store()
    active = store.get("active", {})
    active_id = active.get("providerId")
    active_model = active.get("model")
    providers = store.get("providers", {})

    if active_id and active_id in providers:
        provider = providers[active_id]
        model = active_model or (provider.get("models", [None])[0] if provider.get("models") else None)
        if not model:
            raise RuntimeError(
                f"Provider ativo '{provider.get('name')}' não tem modelo configurado. "
                "Teste o provider ou selecione um modelo em Configurações > LLM Providers."
            )
        # Monta o nome do modelo conforme o tipo para o LiteLLM
        provider_type = provider.get("type", "custom")
        if provider_type == "ollama":
            litellm_model = f"ollama/{model}" if not model.startswith("ollama/") else model
        elif provider_type == "anthropic":
            litellm_model = f"anthropic/{model}" if not model.startswith("anthropic/") else model
        elif provider_type == "azure":
            litellm_model = model  # Azure usa o deployment name diretamente
        else:
            # openai/custom — se o modelo já tem prefixo, usa como está
            litellm_model = model if "/" in model else f"openai/{model}"

        from backend.core.secrets import decrypt_secret
        return litellm_model, provider.get("endpoint") or None, decrypt_secret(provider.get("apiKey"))

    # 3. Nenhum provider ativo
    raise RuntimeError(
        "Nenhum provider LLM ativo configurado. "
        "Configure em Configurações > LLM Providers."
    )


async def _require_terminal_investigation(investigation_id: str, token: Any) -> None:
    """Require an existing case owned by the terminal operator."""
    async with AsyncSessionLocal() as db:
        investigation = await db.scalar(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        if investigation is None:
            raise ValueError("Investigação não encontrada")
        if token.role != "admin" and investigation.owner_id != token.sub:
            raise PermissionError("Esta investigação pertence a outro usuário")


async def _persist_terminal_research(
    investigation_id: str,
    token: Any,
    query: str,
    research: dict[str, Any],
) -> str:
    """Persist redacted terminal research and immutable audit provenance."""
    content = str(research.get("context_md", ""))
    sources = research.get("sources", [])
    evidence = Evidence(
        investigation_id=investigation_id,
        type="osint_search",
        source_url=(sources[0].get("link") if sources and isinstance(sources[0], dict) else None),
        content=content,
        content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        metadata_={
            "query": query,
            "status": research.get("status"),
            "results_count": research.get("results_count", 0),
            "sources": sources,
            "redacted": True,
            "transport": "tor",
        },
    )
    async with AsyncSessionLocal() as db:
        db.add(evidence)
        await db.flush()
        db.add(AuditLog(
            user_id=token.sub,
            action="terminal.research",
            resource_type="investigation",
            resource_id=investigation_id,
            details={"evidence_id": evidence.id, "query": query, "results_count": research.get("results_count", 0)},
        ))
        await db.commit()
        return evidence.id


async def _resolve_rest_model(req: ChatRequest) -> tuple[str, str | None, str | None]:
    """Resolve o modelo para os endpoints REST /api/chat e /api/chat/stream.

    Mesma regra do terminal WS (_resolve_terminal_model):
      1. model explícito no payload (diferente de "auto") → usa como está.
      2. model = "auto" ou ausente → provider ativo do store (Redis).
      3. Sem provider ativo → HTTP 400 com mensagem clara.

    NUNCA cai em settings.litellm_model nem em AutoRouter — o REST segue
    exatamente a decisão do investigador sobre qual provider usar.
    """
    if req.model and req.model != "auto":
        return req.model, None, None
    try:
        model, api_base, api_key = await _resolve_terminal_model(req.model)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    req.model = model
    return model, api_base, api_key


@app.websocket("/ws/v1/terminal")
async def terminal_ws(ws: WebSocket) -> None:
    """Terminal interativo: cliente envia mensagens, servidor responde via LiteLLM.

    Protocolo (JSON):
      → {"type": "chat", "messages": [...], "model": "auto"|"nome"|null}
      ← {"type": "token", "content": "..."}   (streaming)
      ← {"type": "done"}                      (fim da resposta)
      ← {"type": "error", "message": "..."}   (falha)

    Resolução do modelo: payload.model explícito > provider ativo do Redis >
    erro claro (NUNCA cai em settings.litellm_model nem em AutoRouter).
    """
    try:
        token = decode_token(ws.query_params.get("token", ""))
        if token.is_expired or token.token_type != "access":
            raise TokenError("Token inválido")
    except TokenError:
        await ws.close(code=4401, reason="Authentication required")
        return
    await ws.accept()
    logger.info("WebSocket /ws/v1/terminal conectado")
    window_started = time.monotonic()
    messages_in_window = 0
    try:
        while True:
            raw = await ws.receive_text()
            if len(raw) > 256_000:
                await ws.send_json({"type": "error", "message": "Mensagem excede o limite de 256 KB"})
                continue
            now = time.monotonic()
            if now - window_started >= 60:
                window_started, messages_in_window = now, 0
            messages_in_window += 1
            if messages_in_window > 60:
                await ws.send_json({"type": "error", "message": "Limite de 60 mensagens por minuto excedido"})
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_json({"type": "error", "message": "JSON inválido"})
                continue

            if data.get("type") != "chat":
                await ws.send_json({"type": "error", "message": "Tipo não suportado"})
                continue

            try:
                model, api_base, api_key = await _resolve_terminal_model(data.get("model"))
            except RuntimeError as exc:
                await ws.send_json({"type": "error", "message": str(exc)})
                continue

            # Injeta persona OSINT se o cliente não enviou system message próprio (evita recusas genéricas do LLM).
            messages = data.get("messages", [])
            if not isinstance(messages, list) or len(messages) > 50 or any(
                not isinstance(message, dict)
                or message.get("role") not in {"system", "user", "assistant"}
                or not isinstance(message.get("content"), str)
                or len(message["content"]) > 100_000
                for message in messages
            ):
                await ws.send_json({"type": "error", "message": "Formato ou tamanho de mensagens inválido"})
                continue
            if not messages or messages[0].get("role") != "system":
                messages = [{"role": "system", "content": TERMINAL_SYSTEM_PROMPT}, *messages]

            # Pesquisa dark web (estilo argus_engine) quando a mensagem parece uma investigação OSINT.
            # Roda busca nas engines onion via Tor e injeta os resultados como INPUT DATA
            # para o LLM — assim o terminal pesquisa de verdade em vez de recusar.
            research_ctx = ""
            last_user = next(
                (m.get("content", "") for m in reversed(messages) if m.get("role") == "user"),
                "",
            )
            if last_user and _is_research_query(last_user):
                query = last_user[:300]
                investigation_id = str(data.get("investigation_id") or "").strip()
                if not investigation_id:
                    await ws.send_json({
                        "type": "error",
                        "message": "Selecione uma investigação antes de executar pesquisa OSINT.",
                    })
                    continue
                try:
                    await _require_terminal_investigation(investigation_id, token)
                except (ValueError, PermissionError) as exc:
                    await ws.send_json({"type": "error", "message": str(exc)})
                    continue
                await ws.send_json({"type": "research", "status": "searching", "query": query})
                try:
                    research = await run_terminal_research(query, search_only=False)
                except Exception:  # noqa: BLE001
                    logger.exception("Terminal research falhou")
                    research = {"status": "error", "results_count": 0, "context_md": ""}
                evidence_id = None
                if research.get("status") in {"completed", "no_results"}:
                    evidence_id = await _persist_terminal_research(
                        investigation_id, token, query, research
                    )
                await ws.send_json({
                    "type": "research",
                    "status": "done",
                    "results": research.get("results_count", 0),
                    "query": query,
                    "sources": research.get("sources", []),
                    "evidence_id": evidence_id,
                })
                research_ctx = research.get("context_md", "") if research.get("status") == "completed" else ""

            if research_ctx:
                messages = [*messages, {"role": "user", "content": research_ctx}]

            req = ChatRequest(
                messages=messages,
                model=model,
                temperature=data.get("temperature"),
                max_tokens=data.get("max_tokens"),
            )
            try:
                async for event in _llm_stream(req, api_base=api_base, api_key=api_key):
                    await ws.send_text(event)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Falha no streaming via WebSocket")
                await ws.send_json({"type": "error", "message": str(exc)})
    except WebSocketDisconnect:
        logger.info("WebSocket /ws/v1/terminal desconectado")
    except Exception:  # noqa: BLE001
        logger.exception("Erro inesperado no WebSocket")


# ---------------------------------------------------------------------------
# SSE — LLM (eventos de texto livre, sem protocolo de terminal)
# ---------------------------------------------------------------------------
@app.get("/sse/llm")
async def sse_llm(messages: str = "[]", model: str | None = None) -> StreamingResponse:
    """SSE para o LLM. `messages` é um JSON-encoded array de mensagens OpenAI.

    Exemplo:
      GET /sse/llm?messages=[{"role":"user","content":"oi"}]&model=ollama/llama-3
    """
    try:
        parsed = json.loads(messages)
    except json.JSONDecodeError:
        parsed = [{"role": "user", "content": messages}]

    req = ChatRequest(messages=parsed, model=model)
    return StreamingResponse(
        _llm_stream(req),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# WebSocket — notifications (Redis pub/sub → WebSocket)
# ---------------------------------------------------------------------------
@app.websocket("/ws/v1/notifications")
async def notifications_ws(ws: WebSocket) -> None:
    """Stream notifications to connected clients.

    Protocol (JSON):
      → {"type": "subscribe", "user_id": "..."}  (optional, subscribes to user channel)
      → {"type": "ping"}                          (heartbeat)
      ← {"type": "notification", "data": {...}}   (notification payload)
      ← {"type": "pong"}                          (heartbeat response)
      ← {"type": "subscribed", "channel": "..."}  (subscription confirmed)

    The client receives notifications from both the system channel and
    their per-user channel (if user_id is provided).
    """
    try:
        token = decode_token(ws.query_params.get("token", ""))
        if token.is_expired or token.token_type != "access":
            raise TokenError("Token inválido")
    except TokenError:
        await ws.close(code=4401, reason="Authentication required")
        return
    await ws.accept()
    logger.info("WebSocket /ws/v1/notifications conectado")

    user_id: str | None = token.sub
    pubsub = None

    try:
        # Receive optional subscription message
        raw = await ws.receive_text()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            await ws.send_json({"type": "error", "message": "JSON inválido"})
            return

        if data.get("type") == "subscribe" and data.get("user_id") == token.sub:
            user_id = token.sub

        # Subscribe to Redis channels
        if redis_client.is_connected:
            pubsub = redis_client._client.pubsub()
            channels: dict[str, str] = {SYSTEM_CHANNEL: SYSTEM_CHANNEL}
            if user_id:
                channels[USER_CHANNEL.format(user_id=user_id)] = user_id
            await pubsub.subscribe(*channels.keys())
            await ws.send_json({
                "type": "subscribed",
                "channels": list(channels.keys()),
            })
            logger.info(
                "Notifications WS subscribed to: %s",
                list(channels.keys()),
            )
        else:
            await ws.send_json({
                "type": "subscribed",
                "channels": [],
                "warning": "Redis not connected",
            })

        # Main loop: forward Redis messages + handle pings
        while True:
            # Check for Redis messages (non-blocking)
            if pubsub is not None:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.1)
                if message and message["type"] == "message":
                    await ws.send_text(message["data"])

            # Check for client messages (non-blocking with timeout)
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=0.1)
                try:
                    client_data = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                if client_data.get("type") == "ping":
                    await ws.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                pass

    except WebSocketDisconnect:
        logger.info("WebSocket /ws/v1/notifications desconectado")
    except Exception:  # noqa: BLE001
        logger.exception("Erro inesperado no notifications WebSocket")
    finally:
        if pubsub is not None:
            try:
                await pubsub.unsubscribe()
                await pubsub.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Entrypoint — uvicorn
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Force expansion of included routers (FastAPI 0.141.1 workaround)
    app.setup()

    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
