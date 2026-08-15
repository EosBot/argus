"""Pydantic response models for all API endpoints.

These schemas define the JSON structure returned by each endpoint.
All models include proper typing for OpenAPI documentation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# -- Common --------------------------------------------------------------------

class StatusResponse(BaseModel):
    """Generic status response."""

    status: str
    message: str | None = None


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str
    error_code: str | None = None


# -- Auth ----------------------------------------------------------------------

class TokenResponse(BaseModel):
    """JWT token pair response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserInfoResponse(BaseModel):
    """Public user info."""

    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


# -- Search --------------------------------------------------------------------

class SearchResultItem(BaseModel):
    """Single search result."""

    title: str
    link: str


class SearchResponse(BaseModel):
    """Search results response."""

    query: str
    results: list[SearchResultItem]
    total: int
    cached: bool = False


# -- Scrape --------------------------------------------------------------------

class ScrapeResponse(BaseModel):
    """Scrape results response."""

    results: dict[str, str]
    total: int
    cached: bool = False


# -- Pentest -------------------------------------------------------------------

class PentestToolInfo(BaseModel):
    """Pentest tool metadata."""

    name: str
    description: str
    icon: str
    risk_level: str
    available: bool


class PentestScanResponse(BaseModel):
    """Pentest scan result."""

    tool: str
    target: str
    success: bool
    output: str | None = None
    parsed: dict[str, Any] | None = None
    error: str | None = None


class PentestChainResponse(BaseModel):
    """Chained pentest results."""

    target: str
    results: list[PentestScanResponse]
    total_tools: int
    successful: int


# -- Agents --------------------------------------------------------------------

class AgentInfo(BaseModel):
    """Agent metadata."""

    name: str
    description: str
    icon: str
    status: str


class AgentInvokeResponse(BaseModel):
    """Agent invocation response."""

    task_id: str
    agent_name: str
    status: str


class AgentResultResponse(BaseModel):
    """Agent execution result."""

    task_id: str
    agent_name: str
    status: str
    output: dict[str, Any] | None = None
    tags: list[str] = Field(default_factory=list)
    error: str | None = None
    created_at: str | None = None


class AgentSynthesizeResponse(BaseModel):
    """Synthesized multi-agent results."""

    synthesized_at: str
    total_tasks: int
    successful: int
    failed: int
    findings: list[dict[str, Any]]
    errors: list[dict[str, str]]


# -- Investigations ------------------------------------------------------------

class InvestigationResponse(BaseModel):
    """Investigation record."""

    id: str
    title: str
    description: str | None
    status: str
    priority: str
    owner_id: str
    tags: list[str] | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    targets: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationListResponse(BaseModel):
    """Paginated investigation list."""

    items: list[InvestigationResponse]
    total: int
    page: int
    page_size: int


# -- IOCs ----------------------------------------------------------------------

class IOCResponse(BaseModel):
    """IOC record."""

    id: str
    investigation_id: str
    type: str
    value: str
    threat_type: str | None
    severity: str
    source: str | None
    context: dict[str, Any] | None
    created_at: datetime


class IOCListResponse(BaseModel):
    """Paginated IOC list."""

    items: list[IOCResponse]
    total: int
    page: int
    page_size: int


# -- Threats -------------------------------------------------------------------

class ThreatResponse(BaseModel):
    """Threat intelligence record."""

    id: str
    name: str
    description: str | None
    severity: str
    threat_type: str | None
    source: str | None
    indicators: list[str]
    context: dict[str, Any] | None
    created_at: datetime


class ThreatListResponse(BaseModel):
    """Paginated threat list."""

    items: list[ThreatResponse]
    total: int
    page: int
    page_size: int


# -- Evidence ------------------------------------------------------------------

class EvidenceResponse(BaseModel):
    """Evidence record."""

    id: str
    investigation_id: str
    type: str
    source_url: str | None
    content: str | None
    content_hash: str | None
    metadata_: dict[str, Any] | None = Field(default=None, alias="metadata")
    created_at: datetime


class EvidenceListResponse(BaseModel):
    """Paginated evidence list."""

    items: list[EvidenceResponse]
    total: int
    page: int
    page_size: int


# -- Monitoring ----------------------------------------------------------------

class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    service: str
    version: str
    litellm_base_url: str
    model: str
    redis_connected: bool = False
    neo4j_connected: bool = False
    database_connected: bool = False


class SystemStatsResponse(BaseModel):
    """System statistics."""

    investigations_total: int
    investigations_open: int
    iocs_total: int
    findings_total: int
    evidence_total: int
    cache_hit_rate: float | None = None
    active_agents: int = 0
