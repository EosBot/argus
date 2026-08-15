from __future__ import annotations

import json

import pytest

from backend import main
from backend.core.neo4j_client import Neo4jClient


class _Connection:
    async def execute(self, _query):
        return None


class _Engine:
    def __init__(self, *, fails: bool = False) -> None:
        self.fails = fails

    def connect(self):
        engine = self

        class _Context:
            async def __aenter__(self):
                if engine.fails:
                    raise RuntimeError("database unavailable")
                return _Connection()

            async def __aexit__(self, *_args):
                return False

        return _Context()


@pytest.mark.asyncio
async def test_readiness_requires_all_persistence_services(monkeypatch):
    async def healthy():
        return True

    monkeypatch.setattr(main.redis_client, "ping", healthy)
    monkeypatch.setattr(main.neo4j_client, "verify_connectivity", healthy)
    monkeypatch.setattr(main, "engine", _Engine())

    response = await main.readiness()

    assert response.status_code == 200
    assert json.loads(response.body) == {
        "status": "ready",
        "checks": {"postgres": True, "redis": True, "neo4j": True},
    }


@pytest.mark.asyncio
async def test_readiness_returns_503_when_database_is_unavailable(monkeypatch):
    async def healthy():
        return True

    monkeypatch.setattr(main.redis_client, "ping", healthy)
    monkeypatch.setattr(main.neo4j_client, "verify_connectivity", healthy)
    monkeypatch.setattr(main, "engine", _Engine(fails=True))

    response = await main.readiness()

    assert response.status_code == 503
    assert json.loads(response.body)["checks"]["postgres"] is False


@pytest.mark.asyncio
async def test_failed_neo4j_connect_does_not_report_driver_presence(monkeypatch):
    class _Driver:
        closed = False

        async def verify_connectivity(self):
            raise RuntimeError("bad credentials")

        async def close(self):
            self.closed = True

    driver = _Driver()
    monkeypatch.setattr(
        "backend.core.neo4j_client.AsyncGraphDatabase.driver",
        lambda *_args, **_kwargs: driver,
    )
    client = Neo4jClient()

    with pytest.raises(RuntimeError, match="bad credentials"):
        await client.connect()

    assert driver.closed is True
    assert client.is_connected is False
