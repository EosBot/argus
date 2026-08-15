"""Passive connector endpoint, authentication and bounding contracts."""

import json
from types import SimpleNamespace

import httpx
import pytest

from backend.api.routes import operations
from backend.api.routes.operations import ToolExecuteRequest
from backend.tools import connectors


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_id", "target", "host", "auth_header"),
    [
        ("shodan_query", "8.8.8.8", "api.shodan.io", None),
        ("censys_query", "8.8.8.8", "api.platform.censys.io", "authorization"),
        ("virustotal_lookup", "example.org", "www.virustotal.com", "x-apikey"),
        ("abuseipdb_check", "8.8.8.8", "api.abuseipdb.com", "key"),
        ("otx_query", "example.org", "otx.alienvault.com", "x-otx-api-key"),
        ("threatfox_query", "example.org", "threatfox-api.abuse.ch", "auth-key"),
        ("urlhaus_query", "https://example.org/path", "urlhaus-api.abuse.ch", "auth-key"),
    ],
)
async def test_connectors_use_fixed_official_hosts_and_expected_auth(monkeypatch, tool_id, target, host, auth_header):
    seen = {}

    def handler(request: httpx.Request):
        seen["request"] = request
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"ok": True})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        connectors.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    result = await connectors.execute_connector(tool_id, target, "secret-key")
    request = seen["request"]
    assert request.url.host == host
    assert result == {"ok": True}
    if auth_header:
        assert "secret-key" in request.headers[auth_header]
    else:
        assert request.url.params["key"] == "secret-key"


@pytest.mark.asyncio
async def test_connector_rejects_private_ip_without_network_call():
    with pytest.raises(ValueError, match="público"):
        await connectors.execute_connector("abuseipdb_check", "127.0.0.1", "key")


@pytest.mark.asyncio
async def test_urlhaus_rejects_non_http_target_without_network_call():
    with pytest.raises(ValueError, match="HTTP"):
        await connectors.execute_connector("urlhaus_query", "file:///etc/passwd", "key")


@pytest.mark.asyncio
async def test_connector_rejects_oversized_response(monkeypatch):
    real_client = httpx.AsyncClient
    payload = json.dumps({"data": "x" * connectors.MAX_RESPONSE_BYTES}).encode()
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(200, headers={"content-type": "application/json"}, content=payload)
    )
    monkeypatch.setattr(
        connectors.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=transport, follow_redirects=False),
    )
    with pytest.raises(RuntimeError, match="1 MB"):
        await connectors.execute_connector("virustotal_lookup", "example.org", "key")


class FakeSession:
    def __init__(self):
        self.added = []
        self.committed = False

    async def scalar(self, _statement):
        return SimpleNamespace(id="case-1", owner_id="operator-1")

    def add(self, value):
        self.added.append(value)

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_connector_execution_is_redacted_audited_and_attached(monkeypatch):
    async def settings():
        return {"connections": [{"type": "virustotal", "apiKey": "encrypted"}]}

    async def execute(_tool, _target, key):
        assert key == "real-key"
        return {"verdict": "malicious", "password": "should-not-leak"}

    monkeypatch.setattr(operations, "_read_settings", settings)
    monkeypatch.setattr(operations, "decrypt_secret", lambda _value: "real-key")
    monkeypatch.setattr(operations, "execute_connector", execute)
    session = FakeSession()
    response = await operations.execute_tool(
        "virustotal_lookup",
        ToolExecuteRequest(target="example.org", investigation_id="case-1"),
        user=SimpleNamespace(sub="operator-1", role="investigator"),
        db=session,
    )
    assert response["implementation"] == "connector"
    assert response["result"]["password"] == "[REDACTED_CREDENTIAL]"
    assert {type(item).__name__ for item in session.added} == {"Evidence", "AuditLog"}
    assert session.committed is True


@pytest.mark.asyncio
async def test_catalog_exposes_configured_connector_as_available(monkeypatch):
    async def settings():
        return {"tools": {}, "connections": [{"type": "virustotal", "apiKey": "encrypted"}]}

    monkeypatch.setattr(operations, "_read_settings", settings)
    catalog = await operations.list_tools(SimpleNamespace(sub="operator-1", role="investigator"))
    item = next(value for value in catalog["items"] if value["id"] == "virustotal_lookup")
    assert item["availability"] == "available"
    assert item["implementation"] == "connector"
