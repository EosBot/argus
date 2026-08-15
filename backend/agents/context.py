"""Helpers for passing bounded, serializable evidence between agent steps."""

from __future__ import annotations

import json
from typing import Any


def evidence_text(task: dict[str, Any], *, limit: int = 120_000) -> str:
    """Return explicit text plus upstream agent results, bounded for analysis."""
    chunks: list[str] = []
    for key in ("text", "content"):
        value = task.get(key)
        if value:
            chunks.append(str(value))
    previous = task.get("previous_results") or task.get("dependency_results")
    if previous:
        chunks.append(json.dumps(previous, ensure_ascii=False, default=str))
    if not chunks and task.get("query"):
        chunks.append(str(task["query"]))
    return "\n\n".join(chunks)[:limit]
