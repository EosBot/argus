"""Tests for deterministic, non-shell native investigation tools."""

from types import SimpleNamespace

import pytest

from backend.api.routes.operations import ToolExecuteRequest, execute_tool, list_tools
from backend.tools.native import (
    analyze_email_headers,
    analyze_hashes,
    analyze_http_headers,
)


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


def test_hash_analyzer_is_deterministic_and_bounded():
    first = analyze_hashes("evidência")
    second = analyze_hashes("evidência")
    assert first == second
    assert first["digests"]["sha256"] == "a68f4099891b540cf68f620d9b5148b649b73f93df0ab1804a8be2a7fb6f8273"
    assert first["byte_length"] == 10
    assert 0 <= first["entropy_bits_per_byte"] <= 8


def test_email_header_analyzer_excludes_body_and_preserves_route():
    raw = (
        "From: analyst@example.org\nTo: case@example.org\nSubject: Teste\n"
        "Received: from relay.example.org by mx.example.org\n"
        "Authentication-Results: mx.example.org; spf=pass\n\nSEGREDO DO CORPO"
    )
    result = analyze_email_headers(raw)
    assert result["from"] == "analyst@example.org"
    assert len(result["received_chain"]) == 1
    assert "SEGREDO" not in str(result)
    assert result["warnings"] == []


def test_http_header_analyzer_reports_present_and_missing_controls():
    result = analyze_http_headers(
        "HTTP/2 200 OK\r\nContent-Security-Policy: default-src 'none'\r\n"
        "X-Content-Type-Options: nosniff\r\nServer: example/1.0\r\n"
    )
    assert result["status_line"] == "HTTP/2 200 OK"
    assert result["security_headers"]["content-security-policy"] == "default-src 'none'"
    assert result["score"] == 33
    assert any(item["header"] == "strict-transport-security" for item in result["missing_security_headers"])


@pytest.mark.asyncio
async def test_native_execution_is_audited_and_attached_to_case():
    session = FakeSession()
    response = await execute_tool(
        "hash_analyzer",
        ToolExecuteRequest(target="artifact", investigation_id="case-1"),
        user=SimpleNamespace(sub="operator-1", role="investigator"),
        db=session,
    )
    assert response["status"] == "completed"
    assert response["implementation"] == "native"
    assert response["result"]["digests"]["sha256"]
    assert {type(item).__name__ for item in session.added} == {"Evidence", "AuditLog"}
    assert session.committed is True


@pytest.mark.asyncio
async def test_native_tools_are_advertised_as_available(monkeypatch):
    async def settings():
        return {"tools": {}, "connections": []}

    monkeypatch.setattr("backend.api.routes.operations._read_settings", settings)
    catalog = await list_tools(SimpleNamespace(sub="operator-1", role="investigator"))
    by_id = {item["id"]: item for item in catalog["items"]}
    assert by_id["hash_analyzer"]["implementation"] == "native"
    assert by_id["email_header_analyzer"]["availability"] == "available"
    assert by_id["http_header_analyzer"]["implementation"] == "native"


@pytest.mark.asyncio
async def test_agent_tool_rejects_missing_runtime_binary(monkeypatch):
    monkeypatch.setattr("backend.api.routes.operations.shutil.which", lambda _name: None)
    with pytest.raises(Exception) as exc:
        await execute_tool(
            "nmap_scanner",
            ToolExecuteRequest(target="example.org", investigation_id="case-1", authorized=True),
            user=SimpleNamespace(sub="operator-1", role="investigator"),
            db=FakeSession(),
        )
    assert getattr(exc.value, "status_code", None) == 409
    assert "nmap" in str(getattr(exc.value, "detail", ""))
