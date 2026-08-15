"""Safety and persistence tests for bounded system-backed tools."""

from types import SimpleNamespace

import pytest

from backend.api.routes import operations
from backend.api.routes.operations import ToolExecuteRequest
from backend.tools import system


class FakeProcess:
    returncode = 0

    async def communicate(self):
        return (
            (
                b"Domain Name: EXAMPLE.ORG\nRegistrar: Example Registrar\n"
                b"Name Server: NS1.EXAMPLE.ORG\nRegistrant Email: private@example.org\n"
            ),
            b"",
        )

    def kill(self):
        return None


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


@pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.1", "example.org;id", "localhost", "-h"])
def test_whois_rejects_private_or_command_like_targets(target):
    with pytest.raises(ValueError):
        system._whois_target(target)


@pytest.mark.asyncio
async def test_whois_uses_fixed_argv_and_filters_contact_fields(monkeypatch):
    captured = {}

    async def subprocess(*argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(system.asyncio, "create_subprocess_exec", subprocess)
    result = await system.execute_system("whois_lookup", "Example.org.")
    assert captured["argv"] == ("whois", "example.org")
    assert result["fields"]["domain_name"] == "EXAMPLE.ORG"
    assert result["fields"]["name_servers"] == ["NS1.EXAMPLE.ORG"]
    assert "registrant" not in str(result).lower().replace("registrant contact fields omitted", "")
    assert "private@example.org" not in str(result)
    assert len(result["raw_sha256"]) == 64


@pytest.mark.asyncio
async def test_system_execution_is_audited_committed_and_attached(monkeypatch):
    monkeypatch.setattr(operations.shutil, "which", lambda _name: "/usr/bin/whois")

    async def execute(_tool, _target):
        return {"target": "example.org", "fields": {"registrar": "Example"}}

    monkeypatch.setattr(operations, "execute_system", execute)
    session = FakeSession()
    response = await operations.execute_tool(
        "whois_lookup",
        ToolExecuteRequest(target="example.org", investigation_id="case-1"),
        user=SimpleNamespace(sub="operator-1", role="investigator"),
        db=session,
    )
    assert response["implementation"] == "system"
    assert {type(item).__name__ for item in session.added} == {"Evidence", "AuditLog"}
    assert session.committed is True
