"""Tests for credential-free passive APIs routed through Tor."""

from types import SimpleNamespace

import httpx
import pytest

from backend.api.routes import operations
from backend.api.routes.operations import ToolExecuteRequest
from backend.tools import public_api


@pytest.mark.parametrize(
    "target",
    ["http://localhost/admin", "http://127.0.0.1", "http://10.0.0.1", "file:///etc/passwd", "https://user:pass@example.org"],
)
def test_wayback_rejects_local_or_credentialed_targets(target):
    with pytest.raises(ValueError):
        public_api._public_url(target)


@pytest.mark.asyncio
async def test_wayback_uses_fixed_endpoint_tor_and_bounded_shape(monkeypatch):
    observed = {}

    async def handler(request: httpx.Request):
        observed["url"] = str(request.url)
        return httpx.Response(200, json={
            "archived_snapshots": {"closest": {
                "available": True,
                "url": "http://web.archive.org/web/20240101000000/https://example.org/",
                "timestamp": "20240101000000",
                "status": "200",
            }}
        })

    real_client = httpx.AsyncClient

    def client(**kwargs):
        observed["proxy"] = kwargs.get("proxy")
        kwargs.pop("proxy", None)
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(public_api.httpx, "AsyncClient", client)
    monkeypatch.setattr(public_api.settings, "tor_proxy", "socks5h://tor:9050")
    result = await public_api.execute_public_api("wayback_machine", "example.org")
    assert observed["url"].startswith("https://archive.org/wayback/available?")
    assert observed["proxy"] == "socks5h://tor:9050"
    assert result["available"] is True
    assert result["snapshot"]["url"].startswith("http://web.archive.org/web/")
    assert result["transport"] == "tor"


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
async def test_public_api_execution_is_evidence_backed(monkeypatch):
    async def execute(_tool, _target):
        return {"available": False, "source": "Internet Archive", "transport": "tor"}

    monkeypatch.setattr(operations, "execute_public_api", execute)
    session = FakeSession()
    result = await operations.execute_tool(
        "wayback_machine",
        ToolExecuteRequest(target="https://example.org", investigation_id="case-1"),
        user=SimpleNamespace(sub="operator-1", role="investigator"),
        db=session,
    )
    assert result["implementation"] == "public_api"
    assert {type(item).__name__ for item in session.added} == {"Evidence", "AuditLog"}
    assert session.committed is True
