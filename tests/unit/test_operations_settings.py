"""Regression tests for persistent operational settings."""

from types import SimpleNamespace

import pytest

from backend.api.routes import operations


@pytest.mark.asyncio
async def test_first_settings_update_does_not_clear_defaults(monkeypatch):
    stored = {}

    async def get_json(_key):
        return stored.get("value")

    async def set_json(_key, value):
        stored["value"] = value.copy()

    monkeypatch.setattr(operations.redis_client, "get_json", get_json)
    monkeypatch.setattr(operations.redis_client, "set_json", set_json)
    original = operations.copy.deepcopy(operations._settings)
    try:
        response = await operations.update_settings(
            operations.SettingsUpdate(mode="advanced"),
            SimpleNamespace(sub="admin", role="admin"),
        )
        assert response["mode"] == "advanced"
        assert response["opsec"]["level"] == "maximum"
        assert stored["value"]["mode"] == "advanced"
    finally:
        operations._settings.clear()
        operations._settings.update(original)


@pytest.mark.asyncio
async def test_read_settings_merges_legacy_partial_record_with_defaults(monkeypatch):
    async def get_json(_key):
        return {"interface": {"language": "en-US"}}

    monkeypatch.setattr(operations.redis_client, "get_json", get_json)
    settings = await operations._read_settings()
    assert settings["interface"]["language"] == "en-US"
    assert settings["interface"]["reducedMotion"] is False
    assert settings["mode"] == "basic"


@pytest.mark.asyncio
async def test_tool_toggle_preserves_saved_parameters(monkeypatch):
    stored = {
        "value": {
            "tools": {
                "nmap_scanner": {
                    "enabled": True,
                    "parameters": {"ports": "80,443", "timing": "T2"},
                }
            }
        }
    }

    async def get_json(_key):
        return stored["value"]

    async def set_json(_key, value):
        stored["value"] = value

    monkeypatch.setattr(operations.redis_client, "get_json", get_json)
    monkeypatch.setattr(operations.redis_client, "set_json", set_json)
    await operations.update_settings(
        operations.SettingsUpdate(tools={"nmap_scanner": {"enabled": False}}),
        SimpleNamespace(sub="admin", role="admin"),
    )
    saved = stored["value"]["tools"]["nmap_scanner"]
    assert saved["enabled"] is False
    assert saved["parameters"] == {"ports": "80,443", "timing": "T2"}
