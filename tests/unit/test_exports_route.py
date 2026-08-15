"""Contract tests for authenticated investigation exports."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from backend.api.routes.exports import export_investigation


class FakeSession:
    def __init__(self, investigation):
        self.investigation = investigation
        self.added = []

    async def scalar(self, _statement):
        return self.investigation

    def add(self, value):
        self.added.append(value)


def make_investigation(owner_id="operator-1"):
    now = datetime(2026, 8, 14, tzinfo=timezone.utc)
    return SimpleNamespace(
        id="case-1",
        title="Caso de teste",
        description="Escopo autorizado",
        status="active",
        priority="high",
        owner_id=owner_id,
        tags=["test"],
        created_at=now,
        updated_at=now,
        findings=[],
        iocs=[],
        evidence=[],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fmt", "content_type", "magic"),
    [
        ("json", "application/json", b"{"),
        ("csv", "text/csv", b"id,type"),
        ("stix", "application/stix+json", b"{"),
        ("misp", "application/json", b"{"),
        ("sigma", "application/yaml", b""),
        ("yara", "text/plain", b""),
        ("pdf", "application/pdf", b"%PDF"),
        ("timeline", "application/json", b"["),
        ("ioc-package", "application/zip", b"PK"),
    ],
)
async def test_export_formats_are_downloadable_and_audited(fmt, content_type, magic):
    session = FakeSession(make_investigation())
    response = await export_investigation(
        "case-1", fmt, db=session, user=SimpleNamespace(sub="operator-1", role="investigator")
    )

    assert response.media_type.startswith(content_type)
    assert response.body.startswith(magic)
    assert response.headers["cache-control"] == "no-store"
    assert "attachment" in response.headers["content-disposition"]
    assert len(session.added) == 1
    assert session.added[0].action == "investigation.export"


@pytest.mark.asyncio
async def test_export_rejects_cross_owner_access():
    session = FakeSession(make_investigation(owner_id="someone-else"))
    with pytest.raises(HTTPException) as exc:
        await export_investigation(
            "case-1", "json", db=session, user=SimpleNamespace(sub="operator-1", role="investigator")
        )
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_export_rejects_unknown_format_before_database_lookup():
    session = FakeSession(make_investigation())
    with pytest.raises(HTTPException) as exc:
        await export_investigation(
            "case-1", "exe", db=session, user=SimpleNamespace(sub="operator-1", role="investigator")
        )
    assert exc.value.status_code == 400
