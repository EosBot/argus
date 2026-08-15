"""Pydantic request models for all API endpoints.

These schemas validate incoming request bodies and query parameters.
All models use strict validation with descriptive error messages.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# -- Auth ----------------------------------------------------------------------

class LoginRequest(BaseModel):
    """Login credentials."""

    username: str = Field(..., min_length=1, max_length=128, description="Username")
    password: str = Field(..., min_length=1, max_length=256, description="Password")


class RefreshRequest(BaseModel):
    """Refresh token request."""

    refresh_token: str = Field(..., min_length=1, description="Valid refresh token")


# -- Search --------------------------------------------------------------------

class SearchRequest(BaseModel):
    """OSINT search query."""

    query: str = Field(..., min_length=1, max_length=512, description="Search query term")
    max_workers: int = Field(default=5, ge=1, le=16, description="Concurrent search threads")


# -- Scrape --------------------------------------------------------------------

class ScrapeTarget(BaseModel):
    """Single scrape target."""

    link: str = Field(..., min_length=1, max_length=2048, description="URL to scrape")
    title: str = Field(default="Untitled", max_length=512, description="Optional title")


class ScrapeRequest(BaseModel):
    """Batch scrape request."""

    urls: list[ScrapeTarget] = Field(
        ..., min_length=1, max_length=50, description="URLs to scrape",
    )
    max_workers: int = Field(default=5, ge=1, le=16, description="Concurrent scrape threads")


# -- Pentest -------------------------------------------------------------------

class PentestScanRequest(BaseModel):
    """Pentest scan request for a single tool."""

    target: str = Field(..., min_length=1, max_length=512, description="Scan target (host, URL, path)")
    options: dict[str, Any] = Field(
        default_factory=dict, description="Tool-specific options",
    )
    authorized: bool = Field(
        default=False,
        description="Confirmation that you have authorization to scan this target",
    )


class PentestChainRequest(BaseModel):
    """Chain multiple pentest tools against one target."""

    tools: list[str] = Field(
        ..., min_length=1, max_length=9, description="Ordered list of tool names",
    )
    target: str = Field(..., min_length=1, max_length=512, description="Scan target")
    options: dict[str, Any] = Field(default_factory=dict)
    authorized: bool = Field(default=False)


# -- Agents --------------------------------------------------------------------

class AgentInvokeRequest(BaseModel):
    """Invoke a registered agent."""

    agent_name: str = Field(..., min_length=1, max_length=64, description="Registered agent name")
    task: str = Field(..., min_length=1, max_length=4096, description="Task description")
    context: dict[str, Any] = Field(
        default_factory=dict, description="Shared context (target, findings, etc.)",
    )


class AgentParallelRequest(BaseModel):
    """Invoke multiple agents in parallel."""

    tasks: list[AgentInvokeRequest] = Field(
        ..., min_length=1, max_length=8, description="Agents to invoke in parallel",
    )


# -- Investigations ------------------------------------------------------------

class InvestigationCreateRequest(BaseModel):
    """Create a new investigation."""

    title: str = Field(..., min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=8192)
    priority: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    tags: list[str] = Field(default_factory=list, max_length=20)


class InvestigationUpdateRequest(BaseModel):
    """Update an existing investigation."""

    title: str | None = Field(default=None, min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=8192)
    status: str | None = Field(default=None, pattern="^(open|in_progress|closed|archived)$")
    priority: str | None = Field(default=None, pattern="^(low|medium|high|critical)$")
    tags: list[str] | None = Field(default=None, max_length=20)


# -- IOCs ----------------------------------------------------------------------

class IOCCreateRequest(BaseModel):
    """Create an IOC record."""

    type: str = Field(..., min_length=1, max_length=32, description="IOC type (ip, domain, hash, url, email)")
    value: str = Field(..., min_length=1, max_length=1024, description="IOC value")
    threat_type: str | None = Field(default=None, max_length=64)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    source: str | None = Field(default=None, max_length=128)
    context: dict[str, Any] | None = Field(default=None)


# -- Threats -------------------------------------------------------------------

class ThreatCreateRequest(BaseModel):
    """Create a threat intelligence record."""

    name: str = Field(..., min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=8192)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    threat_type: str | None = Field(default=None, max_length=64)
    source: str | None = Field(default=None, max_length=128)
    indicators: list[str] = Field(default_factory=list, max_length=100)
    context: dict[str, Any] | None = Field(default=None)


# -- Evidence ------------------------------------------------------------------

class EvidenceCreateRequest(BaseModel):
    """Create an evidence record."""

    type: str = Field(..., min_length=1, max_length=32, description="Evidence type (scrape, screenshot, document)")
    source_url: str | None = Field(default=None, max_length=2048)
    content: str | None = Field(default=None, max_length=100_000)
    content_hash: str | None = Field(default=None, max_length=128)
    metadata_: dict[str, Any] | None = Field(default=None, alias="metadata")
