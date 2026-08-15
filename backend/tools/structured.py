"""Deterministic structured-data executors for investigation artifacts."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from datetime import datetime
from typing import Any

_BTC_BASE58 = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_BTC_BECH32 = re.compile(r"\bbc1[ac-hj-np-z02-9]{11,71}\b", re.IGNORECASE)
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,63}\b")
_HASH = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _json(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("A ferramenta exige JSON válido") from exc


def identify_wallets(value: str) -> dict[str, Any]:
    """Identify supported public wallet address formats without enrichment."""
    matches: list[dict[str, str]] = []
    seen: set[str] = set()
    for network, pattern, address_type in (
        ("bitcoin", _BTC_BASE58, "base58check-candidate"),
        ("bitcoin", _BTC_BECH32, "bech32-candidate"),
        ("ethereum", _ETH, "hex-address"),
    ):
        for match in pattern.findall(value):
            normalized = match.lower() if network == "ethereum" else match
            if normalized in seen:
                continue
            seen.add(normalized)
            matches.append({"address": match, "network": network, "format": address_type})
    return {
        "addresses": matches,
        "count": len(matches),
        "warning": "A identificação é sintática; propriedade e atividade exigem fonte blockchain autorizada.",
    }


def generate_ioc_report(value: str) -> dict[str, Any]:
    """Extract a bounded IOC summary from supplied text."""
    ips: set[str] = set()
    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value):
        try:
            ips.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    iocs = {
        "ipv4": sorted(ips)[:500],
        "email": sorted(set(_EMAIL.findall(value)))[:500],
        "url": sorted(set(_URL.findall(value)))[:500],
        "hash": sorted(set(_HASH.findall(value)))[:500],
    }
    counts = {kind: len(items) for kind, items in iocs.items()}
    return {"iocs": iocs, "counts": counts, "total": sum(counts.values())}


def generate_threat_report(value: str) -> dict[str, Any]:
    """Create a transparent keyword-based triage summary, never an attribution."""
    report = generate_ioc_report(value)
    lowered = value.lower()
    signals = {
        "credential_exposure": ("credential", "password", "senha", "leak", "breach"),
        "malware": ("malware", "ransomware", "trojan", "payload", "c2"),
        "phishing": ("phishing", "credential harvest", "spoof", "impersonation"),
        "exploitation": ("exploit", "cve-", "vulnerability", "shell", "rce"),
    }
    detected = [name for name, terms in signals.items() if any(term in lowered for term in terms)]
    score = min(100, len(detected) * 20 + min(report["total"], 20) * 2)
    return {
        "triage_score": score,
        "signals": detected,
        "ioc_summary": report["counts"],
        "method": "deterministic-keyword-and-ioc-triage",
        "limitations": "Resultado de triagem; requer validação humana e fontes independentes.",
    }


def generate_timeline(value: str) -> dict[str, Any]:
    """Normalize and chronologically sort JSON events."""
    payload = _json(value)
    events = payload.get("events") if isinstance(payload, dict) else payload
    if not isinstance(events, list):
        raise ValueError("Informe uma lista JSON ou um objeto com a chave events")
    normalized: list[dict[str, Any]] = []
    for index, event in enumerate(events[:2_000]):
        if not isinstance(event, dict):
            continue
        timestamp = str(event.get("timestamp") or event.get("date") or "")[:64]
        try:
            order = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        except (ValueError, OverflowError):
            order = float("inf")
        normalized.append({
            "id": str(event.get("id", index))[:128],
            "timestamp": timestamp,
            "title": str(event.get("title") or event.get("event") or "Evento")[:500],
            "description": str(event.get("description") or "")[:4_000],
            "source": str(event.get("source") or "operator-input")[:500],
            "_order": order,
        })
    normalized.sort(key=lambda item: (item.pop("_order"), item["id"]))
    return {"events": normalized, "count": len(normalized), "truncated": len(events) > 2_000}


def generate_graph(value: str) -> dict[str, Any]:
    """Validate a JSON edge list and return a bounded adjacency graph."""
    payload = _json(value)
    edges = payload.get("edges") if isinstance(payload, dict) else payload
    if not isinstance(edges, list):
        raise ValueError("Informe uma lista JSON ou um objeto com a chave edges")
    adjacency: dict[str, set[str]] = {}
    normalized: list[dict[str, str]] = []
    for edge in edges[:5_000]:
        if not isinstance(edge, dict):
            continue
        source, target = str(edge.get("source", ""))[:256], str(edge.get("target", ""))[:256]
        if not source or not target:
            continue
        adjacency.setdefault(source, set()).add(target)
        adjacency.setdefault(target, set()).add(source)
        normalized.append({"source": source, "target": target, "type": str(edge.get("type", "related"))[:128]})
    nodes = [{"id": node, "degree": len(neighbors)} for node, neighbors in sorted(adjacency.items())]
    return {"nodes": nodes, "edges": normalized, "node_count": len(nodes), "edge_count": len(normalized), "truncated": len(edges) > 5_000}


def export_structured(value: str) -> dict[str, Any]:
    """Normalize JSON and provide a standards-compliant CSV representation."""
    payload = _json(value)
    rows = payload if isinstance(payload, list) else [payload]
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("A exportação exige objeto JSON ou lista de objetos")
    fields = sorted({str(key) for row in rows for key in row})
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows[:5_000]:
        writer.writerow({key: json.dumps(row.get(key), ensure_ascii=False) if isinstance(row.get(key), (dict, list)) else row.get(key, "") for key in fields})
    return {
        "json": payload,
        "csv": output.getvalue(),
        "row_count": min(len(rows), 5_000),
        "columns": fields,
        "truncated": len(rows) > 5_000,
    }


STRUCTURED_EXECUTORS = {
    "wallet_identifier": identify_wallets,
    "ioc_report": generate_ioc_report,
    "threat_report": generate_threat_report,
    "timeline_generator": generate_timeline,
    "graph_visualizer": generate_graph,
    "export_engine": export_structured,
}
