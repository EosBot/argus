"""RBAC and task-visibility contracts for global operations."""

from types import SimpleNamespace

import pytest
import inspect

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from backend.api.routes import operations, providers
from backend.auth.jwt import create_access_token
from backend.orchestrator.dispatcher import AgentDispatcher


def credentials(role: str, subject: str = "operator-1") -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=create_access_token(subject, role))


async def enforce(endpoint, parameter: str, role: str):
    dependency = inspect.signature(endpoint).parameters[parameter].default.dependency
    return await dependency(credentials(role))


@pytest.mark.parametrize(
    ("endpoint",),
    [
        (operations.update_settings,),
        (operations.test_connection,),
        (providers.create_provider,),
        (providers.set_active,),
        (providers.update_provider,),
        (providers.delete_provider,),
        (providers.test_provider,),
    ],
)
@pytest.mark.asyncio
async def test_investigator_cannot_mutate_global_configuration(endpoint):
    with pytest.raises(HTTPException) as exc:
        await enforce(endpoint, "_user", "investigator")
    assert exc.value.status_code == 403
    assert "users:manage" in exc.value.detail


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [providers.list_providers, providers.get_active, operations.get_settings, operations.list_tools])
async def test_investigator_can_read_global_catalogs(endpoint):
    token = await enforce(endpoint, "_user", "investigator")
    assert token.role == "investigator"


@pytest.mark.asyncio
async def test_dispatch_record_persists_operator_identity(monkeypatch):
    stored = {}

    async def set_json(key, value, ex=None):
        stored[key] = value

    monkeypatch.setattr(operations.redis_client, "set_json", set_json)
    dispatcher = AgentDispatcher()
    result = await dispatcher.dispatch("missing-agent", "query", {"operator_id": "operator-1"})
    assert result.owner_id == "operator-1"
    assert stored[f"dispatch:{result.task_id}"]["owner_id"] == "operator-1"


@pytest.mark.asyncio
async def test_agent_status_hides_other_operators(monkeypatch):
    records = {
        "dispatch:mine": {"agent_name": "alpha", "task_id": "mine", "status": "running", "owner_id": "operator-1"},
        "dispatch:other": {"agent_name": "beta", "task_id": "other", "status": "failed", "owner_id": "operator-2"},
    }

    async def keys(_pattern):
        return list(records)

    async def get_json(key):
        return records[key]

    monkeypatch.setattr(operations.redis_client, "keys", keys)
    monkeypatch.setattr(operations.redis_client, "get_json", get_json)
    monkeypatch.setattr(
        operations,
        "get_registry",
        lambda: SimpleNamespace(list_agents=lambda: [
            {"name": "alpha", "description": "A"},
            {"name": "beta", "description": "B"},
        ]),
    )
    output = await operations.agent_status(SimpleNamespace(sub="operator-1", role="investigator"))
    by_name = {item["name"]: item for item in output["items"]}
    assert by_name["alpha"]["task_id"] == "mine"
    assert by_name["beta"]["task_id"] is None
