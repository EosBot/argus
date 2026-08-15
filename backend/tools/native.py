"""Deterministic native tool executors that do not shell out or access networks."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from email import policy
from email.parser import Parser
from typing import Any, Callable

from backend.tools.structured import STRUCTURED_EXECUTORS


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def analyze_hashes(value: str) -> dict[str, Any]:
    """Compute reproducible digests for supplied text without reading host files."""
    raw = value.encode("utf-8")
    return {
        "input_type": "utf-8-text",
        "byte_length": len(raw),
        "entropy_bits_per_byte": round(_entropy(raw), 4),
        "digests": {
            "md5": hashlib.md5(raw, usedforsecurity=False).hexdigest(),
            "sha1": hashlib.sha1(raw, usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "sha512": hashlib.sha512(raw).hexdigest(),
        },
    }


def analyze_email_headers(value: str) -> dict[str, Any]:
    """Parse RFC-style headers; the message body is never returned."""
    header_block = value.split("\n\n", 1)[0].split("\r\n\r\n", 1)[0]
    message = Parser(policy=policy.default).parsestr(header_block, headersonly=True)
    received = message.get_all("received", [])
    authentication = message.get_all("authentication-results", [])
    return {
        "from": str(message.get("from", "")),
        "to": str(message.get("to", "")),
        "reply_to": str(message.get("reply-to", "")),
        "subject": str(message.get("subject", "")),
        "date": str(message.get("date", "")),
        "message_id": str(message.get("message-id", "")),
        "return_path": str(message.get("return-path", "")),
        "received_chain": [str(item) for item in received[:50]],
        "authentication_results": [str(item) for item in authentication[:20]],
        "header_sha256": hashlib.sha256(header_block.encode("utf-8")).hexdigest(),
        "warnings": [] if received else ["Cabeçalho Received ausente; a origem não pode ser encadeada."],
    }


def analyze_http_headers(value: str) -> dict[str, Any]:
    """Assess pasted HTTP response headers without issuing a network request."""
    headers: dict[str, str] = {}
    status_line = ""
    for index, line in enumerate(value.replace("\r\n", "\n").split("\n")[:200]):
        if index == 0 and line.upper().startswith("HTTP/"):
            status_line = line.strip()[:200]
            continue
        if ":" not in line:
            continue
        name, header_value = line.split(":", 1)
        normalized = name.strip().lower()
        if normalized and len(normalized) <= 100:
            headers[normalized] = header_value.strip()[:4_000]
    expected = {
        "content-security-policy": "CSP",
        "strict-transport-security": "HSTS",
        "x-content-type-options": "MIME sniffing protection",
        "x-frame-options": "Frame protection",
        "referrer-policy": "Referrer policy",
        "permissions-policy": "Browser permissions policy",
    }
    present = {name: headers[name] for name in expected if name in headers}
    missing = [{"header": name, "purpose": purpose} for name, purpose in expected.items() if name not in headers]
    return {
        "input_type": "pasted-http-headers",
        "status_line": status_line,
        "header_count": len(headers),
        "security_headers": present,
        "missing_security_headers": missing,
        "score": round(100 * len(present) / len(expected)),
        "server_disclosure": headers.get("server", ""),
    }


NATIVE_EXECUTORS: dict[str, Callable[[str], dict[str, Any]]] = {
    "hash_analyzer": analyze_hashes,
    "email_header_analyzer": analyze_email_headers,
    "http_header_analyzer": analyze_http_headers,
    **STRUCTURED_EXECUTORS,
}


def execute_native(tool_id: str, target: str) -> dict[str, Any]:
    executor = NATIVE_EXECUTORS.get(tool_id)
    if executor is None:
        raise KeyError(tool_id)
    return executor(target)
