"""Gerenciamento de providers LLM.

Endpoints autenticados para configurar provedores LLM.

Contrato de API (fixo — frontend escrito contra este contrato):
  GET    /api/providers              → lista providers + active
  POST   /api/providers              → cria provider (201)
  PUT    /api/providers/{id}         → atualiza provider
  DELETE /api/providers/{id}         → remove provider (204)
  POST   /api/providers/{id}/test    → testa conexão, descobre modelos
  GET    /api/providers/active       → retorna active atual
  PUT    /api/providers/active       → define provider+modelo ativo
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from backend.auth.rbac import require_permission
from backend.core.redis_client import redis_client
from backend.core.secrets import decrypt_secret, encrypt_secret, mask_secret

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/providers", tags=["providers"])

# ---------------------------------------------------------------------------
# Chave Redis e fallback em memória
# ---------------------------------------------------------------------------
REDIS_KEY = "argus:providers"

# Fallback em memória quando Redis está indisponível — nunca 500 por Redis down.
_memory_store: dict[str, Any] = {
    "providers": {},
    "active": {"providerId": None, "model": None},
}


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class ProviderBase(BaseModel):
    name: str = Field(..., min_length=1, description="Nome legível do provider")
    type: str = Field(..., description="Tipo: openai | anthropic | ollama | azure | custom")
    endpoint: str | None = Field(default=None, description="URL base da API")
    apiKey: str | None = Field(default=None, description="Chave de API (opcional para ollama/local)")


class ProviderUpdate(BaseModel):
    name: str | None = None
    type: str | None = None
    endpoint: str | None = None
    apiKey: str | None = None


class ProviderOut(BaseModel):
    id: str
    name: str
    type: str
    endpoint: str
    apiKey: str | None = None  # Mascarado no GET — nunca vaza completa
    status: str  # active | inactive | error
    models: list[str]
    lastChecked: str | None = None


class ActiveSetting(BaseModel):
    providerId: str | None = None
    model: str | None = None


class ActiveResponse(BaseModel):
    active: dict[str, str | None]


class ProvidersListResponse(BaseModel):
    providers: list[ProviderOut]
    active: dict[str, str | None]


class TestResponse(BaseModel):
    ok: bool
    provider: ProviderOut
    error: str | None = None


# ---------------------------------------------------------------------------
# Store helpers (Redis com fallback em memória)
# ---------------------------------------------------------------------------
async def _load_store() -> dict[str, Any]:
    """Carrega o store do Redis; fallback em memória se indisponível."""
    try:
        data = await redis_client.get_json(REDIS_KEY)
        if data is not None:
            migrated = False
            for provider in data.get("providers", {}).values():
                key = provider.get("apiKey")
                encrypted = encrypt_secret(key)
                if encrypted != key:
                    provider["apiKey"] = encrypted
                    migrated = True
            if migrated:
                await redis_client.set_json(REDIS_KEY, data)
                logger.info("Credenciais legadas de providers migradas para armazenamento criptografado")
            return data
    except Exception as exc:  # noqa: BLE001
        logger.warning("Redis indisponível para providers (usando fallback em memória): %s", exc)
    return _memory_store


async def _save_store(store: dict[str, Any]) -> None:
    """Persiste o store no Redis; fallback em memória se indisponível."""
    try:
        await redis_client.set_json(REDIS_KEY, store)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Redis indisponível para persistir providers (mantido em memória): %s", exc)
        global _memory_store
        _memory_store = store


def _mask_key(key: str | None) -> str | None:
    """Mascara a apiKey para exposição: 'sk-***' + últimos 4 caracteres."""
    return mask_secret(key)


def _provider_to_output(provider: dict[str, Any], mask: bool = True) -> ProviderOut:
    """Converte um dict de provider para ProviderOut, mascarando a key se pedido."""
    key = provider.get("apiKey")
    return ProviderOut(
        id=provider["id"],
        name=provider["name"],
        type=provider["type"],
        endpoint=provider.get("endpoint", ""),
        apiKey=_mask_key(key) if mask else key,
        status=provider.get("status", "inactive"),
        models=provider.get("models", []),
        lastChecked=provider.get("lastChecked"),
    )


def _generate_id() -> str:
    """Gera um ID curto para providers: 'prv_' + 12 hex chars."""
    return f"prv_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Teste de conexão por tipo
# ---------------------------------------------------------------------------
async def _test_ollama(endpoint: str) -> tuple[bool, list[str], str | None]:
    """Testa provider Ollama: GET {endpoint}/api/tags."""
    url = endpoint.rstrip("/") + "/api/tags"
    async with httpx.AsyncClient(timeout=8.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
        models = [tag.get("name", "") for tag in data.get("models", [])]
        # Ollama /api/tags retorna {"models": [...]} (não "tags")
        if not models:
            models = [tag.get("name", "") for tag in data.get("tags", [])]
        return True, [m for m in models if m], None


async def _test_openai(endpoint: str, api_key: str | None) -> tuple[bool, list[str], str | None]:
    """Testa provider OpenAI/custom: GET {endpoint}/models com Bearer token."""
    url = endpoint.rstrip("/") + "/models"
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    async with httpx.AsyncClient(timeout=8.0) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        models = [item.get("id", "") for item in data.get("data", [])]
        return True, [m for m in models if m], None


async def _test_anthropic(api_key: str | None) -> tuple[bool, list[str], str | None]:
    """Testa provider Anthropic: GET api.anthropic.com/v1/models."""
    if not api_key:
        return False, [], "apiKey obrigatório para Anthropic"
    url = "https://api.anthropic.com/v1/models"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    async with httpx.AsyncClient(timeout=8.0) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        models = [item.get("id", "") for item in data.get("data", [])]
        return True, [m for m in models if m], None


async def _test_azure(endpoint: str, api_key: str | None) -> tuple[bool, list[str], str | None]:
    """Testa provider Azure: GET {endpoint}/models?api-version=2024-06-01."""
    base = endpoint.rstrip("/")
    urls_tried = [
        f"{base}/models?api-version=2024-06-01",
        f"{base}/models?api-version=2024-02-01",
        f"{base}/models",
    ]
    headers = {}
    if api_key:
        headers["api-key"] = api_key

    last_error: str | None = None
    for url in urls_tried:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                # Azure pode retornar {"data": [...]} ou {"value": [...]}
                items = data.get("data") or data.get("value") or []
                models = [item.get("id", "") or item.get("name", "") for item in items]
                return True, [m for m in models if m], None
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            continue

    return False, [], last_error or "Falha ao conectar ao Azure"


async def _run_connection_test(
    provider_type: str,
    endpoint: str | None,
    api_key: str | None,
) -> tuple[bool, list[str], str | None]:
    """Executa o teste de conexão conforme o tipo do provider."""
    try:
        if provider_type == "ollama":
            if not endpoint:
                return False, [], "endpoint obrigatório para Ollama"
            return await _test_ollama(endpoint)
        elif provider_type == "anthropic":
            return await _test_anthropic(api_key)
        elif provider_type == "azure":
            if not endpoint:
                return False, [], "endpoint obrigatório para Azure"
            return await _test_azure(endpoint, api_key)
        elif provider_type in ("openai", "custom"):
            if not endpoint:
                return False, [], "endpoint obrigatório para OpenAI/custom"
            return await _test_openai(endpoint, api_key)
        else:
            # Tipo desconhecido — tenta como OpenAI-compatible
            if endpoint:
                return await _test_openai(endpoint, api_key)
            return False, [], f"Tipo '{provider_type}' desconhecido e sem endpoint"
    except httpx.TimeoutException:
        return False, [], "Timeout (8s) ao conectar ao provider"
    except httpx.HTTPStatusError as exc:
        return False, [], f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
    except Exception as exc:  # noqa: BLE001
        return False, [], f"Erro inesperado: {exc}"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("", response_model=ProvidersListResponse)
async def list_providers(_user=Depends(require_permission("agents:invoke"))) -> ProvidersListResponse:
    """Lista todos os providers configurados e o provider ativo."""
    store = await _load_store()
    providers = [_provider_to_output(p) for p in store.get("providers", {}).values()]
    active = store.get("active", {"providerId": None, "model": None})
    return ProvidersListResponse(providers=providers, active=active)


@router.post("", response_model=ProviderOut, status_code=status.HTTP_201_CREATED)
async def create_provider(body: ProviderBase, _user=Depends(require_permission("users:manage"))) -> ProviderOut:
    """Cria um novo provider. O status inicial é 'inactive' até ser testado."""
    store = await _load_store()
    provider_id = _generate_id()
    now = datetime.now(timezone.utc).isoformat()
    provider: dict[str, Any] = {
        "id": provider_id,
        "name": body.name,
        "type": body.type,
        "endpoint": body.endpoint or "",
        "apiKey": encrypt_secret(body.apiKey),
        "status": "inactive",
        "models": [],
        "lastChecked": now,
    }
    store.setdefault("providers", {})[provider_id] = provider
    await _save_store(store)
    logger.info("Provider criado: %s (%s)", provider_id, body.name)
    return _provider_to_output(provider)


@router.get("/active", response_model=ActiveResponse)
async def get_active(_user=Depends(require_permission("agents:invoke"))) -> ActiveResponse:
    """Retorna o provider e modelo ativos."""
    store = await _load_store()
    active = store.get("active", {"providerId": None, "model": None})
    return ActiveResponse(active=active)


@router.put("/active", response_model=ActiveResponse)
async def set_active(body: ActiveSetting, _user=Depends(require_permission("users:manage"))) -> ActiveResponse:
    """Define o provider e modelo ativos para o terminal e demais recursos LLM."""
    store = await _load_store()
    providers = store.get("providers", {})

    if body.providerId is None:
        active: dict[str, str | None] = {"providerId": None, "model": None}
        store["active"] = active
        await _save_store(store)
        logger.info("Provider ativo removido")
        return ActiveResponse(active=active)

    if body.providerId not in providers:
        raise HTTPException(
            status_code=404,
            detail=f"Provider '{body.providerId}' não encontrado",
        )

    active: dict[str, str | None] = {"providerId": body.providerId, "model": body.model}
    store["active"] = active
    await _save_store(store)

    provider = providers[body.providerId]
    logger.info(
        "Provider ativo definido: %s (%s) → modelo %s",
        body.providerId, provider.get("name"), body.model,
    )
    return ActiveResponse(active=active)


@router.put("/{provider_id}", response_model=ProviderOut)
async def update_provider(provider_id: str, body: ProviderUpdate, _user=Depends(require_permission("users:manage"))) -> ProviderOut:
    """Atualiza campos de um provider existente."""
    store = await _load_store()
    providers = store.get("providers", {})
    if provider_id not in providers:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' não encontrado")

    provider = providers[provider_id]
    update_data = body.model_dump(exclude_unset=True)
    if "apiKey" in update_data:
        if update_data["apiKey"] and "***" in update_data["apiKey"]:
            update_data.pop("apiKey")
        else:
            update_data["apiKey"] = encrypt_secret(update_data["apiKey"])
    for field, value in update_data.items():
        provider[field] = value

    # Se mudou endpoint/key/type, reseta status para inactive (precisa retestar)
    if any(f in update_data for f in ("endpoint", "apiKey", "type")):
        provider["status"] = "inactive"

    await _save_store(store)
    logger.info("Provider atualizado: %s", provider_id)
    return _provider_to_output(provider)


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(provider_id: str, _user=Depends(require_permission("users:manage"))) -> None:
    """Remove um provider. Se era o ativo, limpa o active."""
    store = await _load_store()
    providers = store.get("providers", {})
    if provider_id not in providers:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' não encontrado")

    del providers[provider_id]

    # Se o provider removido era o ativo, limpa
    active = store.get("active", {})
    if active.get("providerId") == provider_id:
        store["active"] = {"providerId": None, "model": None}

    await _save_store(store)
    logger.info("Provider removido: %s", provider_id)


@router.post("/{provider_id}/test", response_model=TestResponse)
async def test_provider(provider_id: str, _user=Depends(require_permission("users:manage"))) -> TestResponse:
    """Testa a conexão com um provider, descobre modelos e atualiza status."""
    store = await _load_store()
    providers = store.get("providers", {})
    if provider_id not in providers:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' não encontrado")

    provider = providers[provider_id]
    provider_type = provider.get("type", "custom")
    endpoint = provider.get("endpoint")
    api_key = decrypt_secret(provider.get("apiKey"))

    ok, models, error = await _run_connection_test(provider_type, endpoint, api_key)

    now = datetime.now(timezone.utc).isoformat()
    provider["lastChecked"] = now
    if ok:
        provider["status"] = "active"
        provider["models"] = models
    else:
        provider["status"] = "error"
        # Mantém models anteriores em caso de erro
        provider.setdefault("models", [])

    await _save_store(store)
    logger.info(
        "Teste do provider %s: %s (%d modelos)",
        provider_id, "OK" if ok else "FALHA", len(provider.get("models", [])),
    )
    return TestResponse(
        ok=ok,
        provider=_provider_to_output(provider),
        error=error,
    )
