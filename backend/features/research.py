"""Terminal research pipeline — dark web OSINT search with LLM grounding.

Executa o mesmo fluxo de pesquisa do projeto argus_engine, porém voltado ao terminal
WS do ARGUS:

    1. busca nas engines onion via Tor (argus_engine.search.get_search_results)
    2. scrape dos N melhores resultados (argus_engine.scrape.scrape_multiple)
    3. monta um bloco de contexto "INPUT DATA" em markdown, que o LLM usa
       como fonte de grounding (TERMINAL_SYSTEM_PROMPT: STRICT GROUNDING,
       NEVER FABRICATE)

Tudo com timeout total configurável para não travar o terminal.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

# Limites configuráveis via env (evita hardcodes)
SEARCH_TIMEOUT = float(os.environ.get("ARGUS_RESEARCH_SEARCH_TIMEOUT", "25"))
SCRAPE_TIMEOUT = float(os.environ.get("ARGUS_RESEARCH_SCRAPE_TIMEOUT", "30"))
MAX_RESULTS_SCRAPED = int(os.environ.get("ARGUS_RESEARCH_SCRAPE_LIMIT", "5"))
MAX_WORKERS = int(os.environ.get("ARGUS_RESEARCH_MAX_WORKERS", "4"))

_SENSITIVE_PATTERNS = (
    # Common labelled secrets in leak listings or configuration fragments.
    re.compile(
        r"(?i)\b(password|passwd|pwd|senha|secret|token)\s*[:=]\s*([^\s,;]{4,})"
    ),
    # Common combo-list form; retain the account identifier but not the secret.
    re.compile(r"(?im)\b([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\s*:\s*([^\s:]{4,})"),
)


def redact_sensitive_text(value: str) -> tuple[str, int]:
    """Remove likely plaintext credentials before UI/LLM exposure."""
    redacted = value
    count = 0

    def labelled(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"{match.group(1)}: [REDACTED_CREDENTIAL]"

    def combo(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"{match.group(1)}:[REDACTED_CREDENTIAL]"

    redacted = _SENSITIVE_PATTERNS[0].sub(labelled, redacted)
    redacted = _SENSITIVE_PATTERNS[1].sub(combo, redacted)
    return redacted, count


def redact_sensitive_payload(value: Any) -> tuple[Any, int]:
    """Recursively redact secret-bearing fields and credential-like strings."""
    sensitive_keys = {"password", "passwd", "pwd", "senha", "secret", "token", "api_key", "apikey", "authorization"}
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            if str(key).lower().replace("-", "_") in sensitive_keys and item not in (None, ""):
                output[str(key)] = "[REDACTED_CREDENTIAL]"
                count += 1
            else:
                output[str(key)], nested = redact_sensitive_payload(item)
                count += nested
        return output, count
    if isinstance(value, list):
        output_list = []
        count = 0
        for item in value:
            clean, nested = redact_sensitive_payload(item)
            output_list.append(clean)
            count += nested
        return output_list, count
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value, 0


def _run_search_sync(query: str) -> list[dict[str, str]]:
    """Busca síncrona nas engines onion (executada em thread pool).

    Dispara todas as engines em paralelo e acumula resultados parciais
    ate esgotar o orcamento de tempo — engines rapidas retornam de
    imediato, engines mortas sao abandonadas apos o timeout. Isso
    mantem o terminal interativo responsivo (estilo argus_engine).
    """
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from argus_engine.search import fetch_search_results, SEARCH_ENGINES

    results: list[dict[str, str]] = []
    seen: set[str] = set()
    deadline = time.monotonic() + SEARCH_TIMEOUT

    def _collect(fut):
        try:
            items = fut.result(timeout=0.5)
        except Exception:
            return
        if not isinstance(items, list):
            return
        for r in items:
            link = r.get("link") or ""
            if not link or link in seen:
                continue
            seen.add(link)
            results.append({
                "title": str(r.get("title", "Untitled")),
                "link": link,
                "source_engine": str(r.get("source_engine", "unknown")),
            })

    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        futures = [
            executor.submit(fetch_search_results, eng["url"], query, eng["name"])
            for eng in SEARCH_ENGINES
        ]
        for fut in as_completed(futures):
            _collect(fut)
            if time.monotonic() >= deadline:
                break
    finally:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)

    return results


def _run_scrape_sync(results: list[dict[str, str]]) -> dict[str, str]:
    """Scrape síncrono dos resultados (executado em thread pool).

    argus_engine.scrape.scrape_multiple retorna {url: content}.
    """
    from argus_engine.scrape import scrape_multiple

    urls_data = [
        {"link": r["link"], "title": r.get("title", "Untitled")} for r in results
    ]
    return scrape_multiple(urls_data, max_workers=MAX_WORKERS)


def _build_context_markdown(
    query: str,
    results: list[dict[str, str]],
    scraped: dict[str, str],
) -> str:
    """Monta o bloco de grounding em markdown para o LLM.

    Args:
        query: query original do investigador.
        results: resultados das engines onion [{title, link}].
        scraped: dict {url: content} com o conteúdo raspado.
    """
    lines: list[str] = [
        f"### OSINT SEARCH RESULTS (INPUT DATA)",
        f"Query: {query}",
        "",
        f"Total results from dark web engines: {len(results)}",
        "",
    ]

    # Índice de resultados por link para cruzar com o scrape
    link_index = {r.get("link"): r.get("title", "Untitled") for r in results}
    engine_index = {r.get("link"): r.get("source_engine", "unknown") for r in results}

    for i, (link, content) in enumerate(scraped.items(), start=1):
        title = str(link_index.get(link, "Untitled"))
        lines.append(f"---")
        lines.append(f"### Result {i}: {title}")
        lines.append(f"Source: {link}")
        lines.append(f"Search engine: {engine_index.get(link, 'unknown')}")
        if content:
            # Limita o trecho para não estourar o contexto do LLM
            snippet, redaction_count = redact_sensitive_text(
                str(content)[:2000].strip()
            )
            lines.append(snippet)
            if redaction_count:
                lines.append(
                    f"[ARGUS: {redaction_count} possível(is) credencial(is) redigida(s)]"
                )
        lines.append("")

    lines.append("---")
    lines.append(
        "Analyze the data above STRICTLY. Do NOT fabricate artifacts that are "
        "not present in this INPUT DATA."
    )
    return "\n".join(lines)


async def run_terminal_research(
    query: str,
    search_only: bool = False,
) -> dict[str, Any]:
    """Executa a pesquisa do argus_engine para o terminal, com timeout global.

    Args:
        query: termo de busca do investigador.
        search_only: se True, faz apenas a busca nas engines onion (sem scrape).
                     Use no terminal WS para manter latência interativa.

    Returns:
        dict com:
          - query: query original
          - status: "completed" | "no_results" | "error"
          - results_count: total de resultados das engines
          - context_md: bloco markdown pronto para o LLM (ou "")
          - error: mensagem de erro (se status == "error")
    """
    loop = asyncio.get_event_loop()

    try:
        results_raw = await loop.run_in_executor(None, _run_search_sync, query)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Terminal research: search failed para %r", query)
        return {
            "query": query,
            "status": "error",
            "results_count": 0,
            "context_md": "",
            "error": str(exc),
        }

    results = [
        {
            "title": str(r.get("title", "Untitled")),
            "link": str(r.get("link", "")),
            "source_engine": str(r.get("source_engine", "unknown")),
        }
        for r in results_raw
        if r.get("link")
    ]
    if not results:
        return {
            "query": query,
            "status": "no_results",
            "results_count": 0,
            "context_md": "",
            "error": "",
        }

    scraped: dict[str, str] = {}
    if not search_only:
        top = results[:MAX_RESULTS_SCRAPED]
        try:
            scraped = await asyncio.wait_for(
                loop.run_in_executor(None, _run_scrape_sync, top),
                timeout=SCRAPE_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.warning("Terminal research: scrape timeout (%.0fs)", SCRAPE_TIMEOUT)
        except Exception:  # noqa: BLE001
            logger.exception("Terminal research: scrape failed")

    if not scraped:
        scraped = {r["link"]: "" for r in results[:MAX_RESULTS_SCRAPED]}

    context_md = _build_context_markdown(query, results, scraped)
    return {
        "query": query,
        "status": "completed",
        "results_count": len(results),
        "sources": results[:MAX_RESULTS_SCRAPED],
        "context_md": context_md,
        "error": "",
    }
