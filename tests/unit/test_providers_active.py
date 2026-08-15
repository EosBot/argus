"""Provider active-selection contract tests."""

from types import SimpleNamespace

import pytest

from backend.api.routes import providers


@pytest.mark.asyncio
async def test_active_provider_can_be_cleared(monkeypatch):
    store = {
        "providers": {"prv_test": {"id": "prv_test", "name": "Test", "type": "custom"}},
        "active": {"providerId": "prv_test", "model": "model-a"},
    }

    async def load():
        return store

    async def save(value):
        assert value["active"] == {"providerId": None, "model": None}

    monkeypatch.setattr(providers, "_load_store", load)
    monkeypatch.setattr(providers, "_save_store", save)
    result = await providers.set_active(
        providers.ActiveSetting(providerId=None, model=None),
        SimpleNamespace(sub="admin", role="admin"),
    )
    assert result.active == {"providerId": None, "model": None}


@pytest.mark.asyncio
async def test_unknown_active_provider_is_rejected(monkeypatch):
    async def load():
        return {"providers": {}, "active": {"providerId": None, "model": None}}

    monkeypatch.setattr(providers, "_load_store", load)
    with pytest.raises(Exception) as exc:
        await providers.set_active(
            providers.ActiveSetting(providerId="missing", model="x"),
            SimpleNamespace(sub="admin", role="admin"),
        )
    assert getattr(exc.value, "status_code", None) == 404


@pytest.mark.asyncio
async def test_loading_legacy_provider_encrypts_plaintext_key(monkeypatch):
    store = {"providers": {"legacy": {"apiKey": "plain-secret"}}, "active": {}}
    saved = {}

    async def get_json(_key):
        return store

    async def set_json(_key, value):
        saved.update(value)

    monkeypatch.setattr(providers.redis_client, "get_json", get_json)
    monkeypatch.setattr(providers.redis_client, "set_json", set_json)
    loaded = await providers._load_store()
    encrypted = loaded["providers"]["legacy"]["apiKey"]
    assert encrypted.startswith("enc:v1:")
    assert providers.decrypt_secret(encrypted) == "plain-secret"
    assert saved["providers"]["legacy"]["apiKey"] == encrypted
