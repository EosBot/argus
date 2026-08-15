"""Tests for deterministic structured investigation tools."""

import pytest
from fastapi import HTTPException

from backend.api.routes import operations
from backend.tools.native import NATIVE_EXECUTORS, execute_native


def test_wallet_identifier_is_syntactic_and_deduplicated():
    address = "0x52908400098527886E0F7030069857D2E4169EE7"
    result = execute_native("wallet_identifier", f"{address} {address}")
    assert result["count"] == 1
    assert result["addresses"][0]["network"] == "ethereum"
    assert "sintática" in result["warning"]


def test_ioc_and_threat_reports_are_transparent():
    text = "Possible ransomware at https://example.test/a from 8.8.8.8; mail a@example.test"
    iocs = execute_native("ioc_report", text)
    threat = execute_native("threat_report", text)
    assert iocs["total"] == 3
    assert threat["signals"] == ["malware"]
    assert threat["method"] == "deterministic-keyword-and-ioc-triage"


def test_timeline_normalizes_and_sorts_events():
    result = execute_native(
        "timeline_generator",
        '[{"id":"b","timestamp":"2026-02-01T00:00:00Z"},'
        '{"id":"a","timestamp":"2026-01-01T00:00:00Z"}]',
    )
    assert [event["id"] for event in result["events"]] == ["a", "b"]


def test_graph_validates_edges_and_computes_degree():
    result = execute_native(
        "graph_visualizer",
        '{"edges":[{"source":"a","target":"b"},{"source":"a","target":"c"}]}',
    )
    assert result["node_count"] == 3
    assert result["nodes"][0] == {"id": "a", "degree": 2}


def test_export_engine_produces_csv_and_preserves_json():
    result = execute_native("export_engine", '[{"name":"á"},{"name":"b"}]')
    assert result["row_count"] == 2
    assert "name" in result["csv"]
    assert result["json"][0]["name"] == "á"


@pytest.mark.parametrize("tool_id", ["timeline_generator", "graph_visualizer", "export_engine"])
def test_structured_json_tools_reject_invalid_json(tool_id):
    with pytest.raises(ValueError, match="JSON válido"):
        execute_native(tool_id, "not-json")


def test_all_new_executors_are_registered():
    expected = {"wallet_identifier", "ioc_report", "threat_report", "timeline_generator", "graph_visualizer", "export_engine"}
    assert expected <= NATIVE_EXECUTORS.keys()


@pytest.mark.asyncio
async def test_execute_route_turns_invalid_native_input_into_http_400(monkeypatch):
    class FakeDB:
        async def scalar(self, _query):
            return type("Investigation", (), {"owner_id": "operator"})()

    with pytest.raises(HTTPException) as exc_info:
        await operations.execute_tool(
            "timeline_generator",
            operations.ToolExecuteRequest(target="not-json", investigation_id="case-1"),
            type("User", (), {"sub": "operator", "role": "analyst"})(),
            FakeDB(),
        )
    assert exc_info.value.status_code == 400
    assert "JSON válido" in exc_info.value.detail
