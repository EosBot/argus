"""Operational tool defaults and execution-context regression tests."""

from types import SimpleNamespace

import pytest

from backend.api.routes import operations
from backend.tools import get_tool_registry as get_package_registry
from backend.tools.configuration import (
    TOOL_DEFAULT_PARAMETERS,
    defaults_for,
    validate_parameters,
)
from backend.tools.registry import get_tool_registry as get_module_registry


def test_defaults_are_non_secret_and_copied():
    assert TOOL_DEFAULT_PARAMETERS
    serialized_keys = " ".join(
        key.lower() for parameters in TOOL_DEFAULT_PARAMETERS.values() for key in parameters
    )
    assert "api_key" not in serialized_keys
    first = defaults_for("nmap_scanner")
    first["timeout_seconds"] = 1
    assert defaults_for("nmap_scanner")["timeout_seconds"] == 120


def test_tools_package_exposes_the_canonical_singleton():
    assert get_package_registry() is get_module_registry()
    assert len(get_package_registry()) == 36


def test_parameter_validation_coerces_ui_values_and_enforces_bounds():
    assert validate_parameters(
        "tor_crawler", {"timeout_seconds": "30", "rotate_circuit": "false"}
    ) == {"timeout_seconds": 30, "rotate_circuit": False}
    with pytest.raises(ValueError, match="entre 1 e 600"):
        validate_parameters("tor_crawler", {"timeout_seconds": "9999"})
    with pytest.raises(ValueError, match="não permitidos"):
        validate_parameters("tor_crawler", {"api_key": "must-not-be-here"})


@pytest.mark.asyncio
async def test_settings_reject_unknown_tools(monkeypatch):
    async def read_settings():
        return {"tools": {}, "connections": []}

    monkeypatch.setattr(operations, "_read_settings", read_settings)
    with pytest.raises(Exception) as exc_info:
        await operations.update_settings(
            operations.SettingsUpdate(tools={"invented": {"enabled": True}}),
            SimpleNamespace(sub="admin", role="admin"),
        )
    assert getattr(exc_info.value, "status_code", None) == 400


@pytest.mark.asyncio
async def test_list_tools_merges_defaults_with_saved_overrides(monkeypatch):
    async def read_settings():
        return {"tools": {"nmap_scanner": {"parameters": {"timing": "T2"}}}, "connections": []}

    monkeypatch.setattr(operations, "_read_settings", read_settings)
    response = await operations.list_tools(SimpleNamespace())
    nmap = next(item for item in response["items"] if item["id"] == "nmap_scanner")
    assert nmap["parameters"]["timing"] == "T2"
    assert nmap["parameters"]["timeout_seconds"] == 120


@pytest.mark.asyncio
async def test_catalog_has_no_entry_without_executor(monkeypatch):
    async def read_settings():
        return {"tools": {}, "connections": []}

    monkeypatch.setattr(operations, "_read_settings", read_settings)
    response = await operations.list_tools(SimpleNamespace())
    unsupported = {
        "catalog_only", "binary_without_executor", "connector_without_executor"
    }
    assert response["total"] == 36
    assert not [item for item in response["items"] if item["implementation"] in unsupported]


@pytest.mark.asyncio
async def test_agent_execution_receives_persisted_parameters(monkeypatch):
    class FakeDB:
        records = []

        async def scalar(self, _query):
            return SimpleNamespace(owner_id="operator")

        def add(self, record):
            self.records.append(record)

        async def commit(self):
            return None

    async def read_settings():
        return {"tools": {"username_search": {"parameters": {"max_results": 7}}}}

    captured = {}

    async def dispatch(agent_name, task, context):
        captured.update(context)
        return SimpleNamespace(task_id="task-1", status="queued")

    monkeypatch.setattr(operations, "_read_settings", read_settings)
    monkeypatch.setattr(operations.dispatcher, "dispatch", dispatch)
    await operations.execute_tool(
        "username_search",
        operations.ToolExecuteRequest(target="alice", investigation_id="case-1"),
        SimpleNamespace(sub="operator", role="analyst"),
        FakeDB(),
    )
    assert captured["max_results"] == 7
    assert captured["timeout_seconds"] == 15


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_id", "address", "chain"),
    [
        ("btc_tracer", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "btc"),
        ("eth_tracer", "0x52908400098527886E0F7030069857D2E4169EE7", "eth"),
    ],
)
async def test_crypto_tools_dispatch_the_agent_contract(
    monkeypatch, tool_id, address, chain
):
    class FakeDB:
        async def scalar(self, _query):
            return SimpleNamespace(owner_id="operator")

        def add(self, _record):
            return None

        async def commit(self):
            return None

    async def read_settings():
        return {"tools": {}}

    captured = {}

    async def dispatch(_agent_name, _task, context):
        captured.update(context)
        return SimpleNamespace(task_id="task-crypto", status="queued")

    monkeypatch.setattr(operations, "_read_settings", read_settings)
    monkeypatch.setattr(operations.dispatcher, "dispatch", dispatch)
    await operations.execute_tool(
        tool_id,
        operations.ToolExecuteRequest(target=address, investigation_id="case-1"),
        SimpleNamespace(sub="operator", role="analyst"),
        FakeDB(),
    )
    assert captured["address"] == address
    assert captured["chain"] == chain


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_id", "geolocate", "discover"),
    [
        ("ioc_extractor", False, False),
        ("ip_geolocator", True, False),
        ("subdomain_discoverer", False, True),
    ],
)
async def test_forensic_tools_dispatch_distinct_modes(
    monkeypatch, tool_id, geolocate, discover
):
    class FakeDB:
        async def scalar(self, _query):
            return SimpleNamespace(owner_id="operator")

        def add(self, _record):
            return None

        async def commit(self):
            return None

    async def read_settings():
        return {"tools": {}}

    captured = {}

    async def dispatch(_agent_name, _task, context):
        captured.update(context)
        return SimpleNamespace(task_id="task-forensic", status="queued")

    monkeypatch.setattr(operations, "_read_settings", read_settings)
    monkeypatch.setattr(operations.dispatcher, "dispatch", dispatch)
    await operations.execute_tool(
        tool_id,
        operations.ToolExecuteRequest(target="example.org", investigation_id="case-1"),
        SimpleNamespace(sub="operator", role="analyst"),
        FakeDB(),
    )
    assert captured["geolocate"] is geolocate
    assert captured["discover_subdomains"] is discover


@pytest.mark.asyncio
async def test_infrastructure_parameters_are_nested_as_scanner_options(monkeypatch):
    class FakeDB:
        async def scalar(self, _query):
            return SimpleNamespace(owner_id="operator")

        def add(self, _record):
            return None

        async def commit(self):
            return None

    async def read_settings():
        return {"tools": {"nmap_scanner": {"parameters": {"timing": "T2"}}}}

    captured = {}

    async def dispatch(_agent_name, _task, context):
        captured.update(context)
        return SimpleNamespace(task_id="task-infra", status="queued")

    monkeypatch.setattr(operations, "_read_settings", read_settings)
    monkeypatch.setattr(operations.dispatcher, "dispatch", dispatch)
    monkeypatch.setattr(operations.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    await operations.execute_tool(
        "nmap_scanner",
        operations.ToolExecuteRequest(
            target="example.org", investigation_id="case-1", authorized=True
        ),
        SimpleNamespace(sub="operator", role="admin"),
        FakeDB(),
    )
    assert captured["tools"] == ["nmap"]
    assert captured["options"]["ports"] == "1-100"
    assert captured["options"]["timing"] == "T2"
