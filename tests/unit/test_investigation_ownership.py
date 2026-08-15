"""Ownership is enforced consistently before orchestrator operations."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from backend.orchestrator.integration import _owned_investigation
from backend.api.routes.investigations import delete_investigation


class FakeSession:
    def __init__(self, investigation):
        self.investigation = investigation

    async def scalar(self, _query):
        return self.investigation


@pytest.mark.asyncio
async def test_owner_can_access_investigation() -> None:
    investigation = SimpleNamespace(owner_id="operator-a")
    user = SimpleNamespace(sub="operator-a", role="investigator")

    assert (
        await _owned_investigation(FakeSession(investigation), "case-1", user)
        is investigation
    )


@pytest.mark.asyncio
async def test_other_investigator_is_denied() -> None:
    investigation = SimpleNamespace(owner_id="operator-a")
    user = SimpleNamespace(sub="operator-b", role="investigator")

    with pytest.raises(HTTPException) as error:
        await _owned_investigation(FakeSession(investigation), "case-1", user)

    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_supervise_investigation() -> None:
    investigation = SimpleNamespace(owner_id="operator-a")
    admin = SimpleNamespace(sub="supervisor", role="admin")

    assert (
        await _owned_investigation(FakeSession(investigation), "case-1", admin)
        is investigation
    )


@pytest.mark.asyncio
async def test_missing_investigation_is_not_disclosed() -> None:
    user = SimpleNamespace(sub="operator-a", role="investigator")

    with pytest.raises(HTTPException) as error:
        await _owned_investigation(FakeSession(None), "missing", user)

    assert error.value.status_code == 404


@pytest.mark.asyncio
async def test_delete_rejects_non_owner() -> None:
    investigation = SimpleNamespace(owner_id="operator-a")

    class Result:
        def scalar_one_or_none(self):
            return investigation

    class Session:
        deleted = False

        async def execute(self, _query):
            return Result()

        async def delete(self, _investigation):
            self.deleted = True

        async def commit(self):
            return None

    session = Session()
    with pytest.raises(HTTPException) as error:
        await delete_investigation(
            "case-1",
            session,
            SimpleNamespace(sub="operator-b", role="investigator"),
        )

    assert error.value.status_code == 403
    assert session.deleted is False
