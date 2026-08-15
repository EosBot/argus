"""Non-secret defaults for operational tool configuration.

Credentials belong to encrypted provider/connection records.  This module only
contains bounded execution controls that may safely be shown in the UI.
"""

from __future__ import annotations

from typing import Any

COMMON_PASSIVE = {"timeout_seconds": 15, "max_results": 25}
COMMON_ACTIVE = {"timeout_seconds": 120, "max_results": 100}

TOOL_DEFAULT_PARAMETERS: dict[str, dict[str, Any]] = {
    "tor_crawler": {**COMMON_PASSIVE, "max_depth": 2, "rotate_circuit": True},
    "onion_search": {**COMMON_PASSIVE, "max_results": 50},
    "ioc_extractor": {"max_indicators": 500, "deduplicate": True},
    "ip_geolocator": {**COMMON_PASSIVE, "include_raw_provider_data": False},
    "subdomain_discoverer": {**COMMON_PASSIVE, "max_results": 100},
    "wayback_machine": {"timeout_seconds": 15},
    "hash_analyzer": {},
    "email_header_analyzer": {},
    "http_header_analyzer": {},
    "btc_tracer": {**COMMON_PASSIVE, "max_transactions": 100},
    "eth_tracer": {**COMMON_PASSIVE, "max_transactions": 100},
    "wallet_identifier": {},
    "username_search": {**COMMON_PASSIVE, "max_results": 100},
    "email_lookup": {**COMMON_PASSIVE, "max_results": 50},
    "nmap_scanner": {**COMMON_ACTIVE, "ports": "1-100", "timing": "T3"},
    "nuclei_scanner": {**COMMON_ACTIVE, "severity": "medium,high,critical", "rate_limit": 10},
    "subfinder": {**COMMON_PASSIVE, "max_results": 500},
    "dns_resolver": {"timeout_seconds": 15, "record_types": "A,AAAA,MX,NS,TXT,CNAME"},
    "whois_lookup": {"timeout_seconds": 15, "include_personal_contacts": False},
    "ssl_analyzer": {**COMMON_PASSIVE, "verify_certificate": True},
    "technology_detector": {**COMMON_PASSIVE, "max_redirects": 0},
    "shodan_query": {**COMMON_PASSIVE, "max_results": 25},
    "censys_query": {"timeout_seconds": 15},
    "virustotal_lookup": {**COMMON_PASSIVE, "max_results": 10},
    "abuseipdb_check": {"timeout_seconds": 15, "max_age_days": 90},
    "otx_query": {**COMMON_PASSIVE, "max_results": 25},
    "threatfox_query": {**COMMON_PASSIVE, "exact_match": True},
    "urlhaus_query": {"timeout_seconds": 15},
    "attribution_engine": {"minimum_confidence": 0.7, "require_independent_sources": 2},
    "github_leak_scanner": {**COMMON_ACTIVE, "redact_secrets": True},
    "report_generator": {"language": "pt-BR", "include_sources": True},
    "ioc_report": {"max_indicators": 500},
    "threat_report": {"require_human_review": True},
    "timeline_generator": {"max_events": 2000},
    "graph_visualizer": {"max_edges": 5000},
    "export_engine": {"max_rows": 5000, "formats": "json,csv"},
}


def defaults_for(tool_id: str) -> dict[str, Any]:
    """Return a copy so callers cannot mutate global defaults."""
    return dict(TOOL_DEFAULT_PARAMETERS.get(tool_id, {}))


def _coerce_bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    raise ValueError(f"{field} deve ser booleano")


def _coerce_number(value: Any, template: int | float, field: str) -> int | float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} deve ser numérico") from exc
    if isinstance(template, int):
        if not number.is_integer():
            raise ValueError(f"{field} deve ser inteiro")
        return int(number)
    return number


def validate_parameters(tool_id: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """Validate and coerce a partial non-secret tool configuration."""
    schema = TOOL_DEFAULT_PARAMETERS.get(tool_id)
    if schema is None:
        if parameters:
            raise ValueError(f"{tool_id} não possui parâmetros configuráveis")
        return {}
    unknown = sorted(set(parameters) - set(schema))
    if unknown:
        raise ValueError(f"Parâmetros não permitidos para {tool_id}: {', '.join(unknown)}")
    output: dict[str, Any] = {}
    for field, value in parameters.items():
        template = schema[field]
        if isinstance(template, bool):
            coerced = _coerce_bool(value, field)
        elif isinstance(template, (int, float)):
            coerced = _coerce_number(value, template, field)
        elif isinstance(template, str):
            coerced = str(value).strip()
            if not coerced or len(coerced) > 500:
                raise ValueError(f"{field} deve conter entre 1 e 500 caracteres")
        else:
            raise ValueError(f"Schema inválido para {tool_id}.{field}")
        if field == "timeout_seconds" and not 1 <= coerced <= 600:
            raise ValueError("timeout_seconds deve estar entre 1 e 600")
        if field.startswith("max_") and not 1 <= coerced <= 5_000:
            raise ValueError(f"{field} deve estar entre 1 e 5000")
        if field in {"minimum_confidence"} and not 0 <= coerced <= 1:
            raise ValueError(f"{field} deve estar entre 0 e 1")
        if field == "rate_limit" and not 1 <= coerced <= 1_000:
            raise ValueError("rate_limit deve estar entre 1 e 1000")
        if field == "max_depth" and not 1 <= coerced <= 10:
            raise ValueError("max_depth deve estar entre 1 e 10")
        if field == "timing" and coerced not in {"T0", "T1", "T2", "T3", "T4"}:
            raise ValueError("timing deve estar entre T0 e T4")
        output[field] = coerced
    return output
