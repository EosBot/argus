"""TAXII 2.1 server — FastAPI router.

Implements the TAXII 2.1 specification endpoints:

    GET  /taxii2/                              → Server Discovery
    GET  /taxii2/api1/                          → API Root Information
    GET  /taxii2/api1/collections/              → List Collections
    GET  /taxii2/api1/collections/{id}/         → Get Collection
    GET  /taxii2/api1/collections/{id}/manifest/ → Get Object Manifest
    GET  /taxii2/api1/collections/{id}/objects/  → Get Objects (envelope)
    POST /taxii2/api1/collections/{id}/objects/  → Add Objects (STIX bundle)

All responses use Content-Type: application/taxii+json;version=2.1
Pagination headers X-TAXII-Date-Added-First/Last are included per spec.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from backend.auth.rbac import require_permission
from backend.core.config import settings
from backend.export.taxii import TAXII_CONTENT_TYPE, DEFAULT_API_ROOT

# asyncpg is a project dependency (via SQLAlchemy asyncpg driver).
# Imported lazily so the module loads even if only the TAXIIExporter is needed.
import asyncpg  # noqa: E402 — kept here for runtime; see _get_db()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router — mounted at /taxii2 in main.py
# ---------------------------------------------------------------------------
router = APIRouter(tags=["taxii"])

# Default pagination settings
DEFAULT_LIMIT = 50
MAX_LIMIT = 1000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dsn() -> str:
    """Convert SQLAlchemy asyncpg URL to asyncpg-compatible DSN."""
    return settings.database_url.replace("postgresql+asyncpg://", "postgresql://", 1)


async def _get_db() -> asyncpg.Connection:
    """Open an asyncpg connection."""
    return await asyncpg.connect(_dsn())


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _taxii_response(content: dict[str, Any], **headers: str) -> Response:
    """Build a TAXII 2.1 response with the mandatory Content-Type header."""
    extra = {"Content-Type": TAXII_CONTENT_TYPE}
    extra.update(headers)
    return Response(
        content=json.dumps(content, default=str),
        media_type=TAXII_CONTENT_TYPE,
        headers=extra,
    )


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

async def _ensure_tables() -> None:
    """Create TAXII tables if they don't exist (dev convenience)."""
    conn = await _get_db()
    try:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS taxii_collections (
                id UUID PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                can_read BOOLEAN DEFAULT true,
                can_write BOOLEAN DEFAULT false,
                media_types TEXT[] DEFAULT '{"application/stix+json;version=2.1"}',
                created_at TIMESTAMPTZ DEFAULT now()
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS taxii_objects (
                id TEXT PRIMARY KEY,
                collection_id UUID REFERENCES taxii_collections(id),
                type TEXT NOT NULL,
                created TIMESTAMPTZ,
                modified TIMESTAMPTZ,
                object JSONB NOT NULL,
                date_added TIMESTAMPTZ DEFAULT now()
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_taxii_objects_collection "
            "ON taxii_objects(collection_id)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_taxii_objects_type "
            "ON taxii_objects(type)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_taxii_objects_date "
            "ON taxii_objects(date_added)"
        )
    finally:
        await conn.close()


async def _seed_default_collection() -> None:
    """Insert a default collection if none exist."""
    conn = await _get_db()
    try:
        row = await conn.fetchrow("SELECT COUNT(*) AS cnt FROM taxii_collections")
        if row["cnt"] == 0:
            await conn.execute(
                """
                INSERT INTO taxii_collections (id, title, description, can_read, can_write)
                VALUES ($1, $2, $3, true, true)
                """,
                str(uuid.uuid5(uuid.NAMESPACE_DNS, "argus:default-collection")),
                "Default Threat Intelligence Collection",
                "Auto-generated collection for ARGUS investigations",
            )
            logger.info("Seeded default TAXII collection")
    finally:
        await conn.close()


async def _get_collections() -> list[dict[str, Any]]:
    """Fetch all TAXII collections."""
    conn = await _get_db()
    try:
        rows = await conn.fetch(
            "SELECT id, title, description, can_read, can_write, media_types, "
            "created_at FROM taxii_collections ORDER BY created_at"
        )
        return [dict(r) for r in rows]
    finally:
        await conn.close()


async def _get_collection(collection_id: str) -> dict[str, Any] | None:
    """Fetch a single collection by ID."""
    conn = await _get_db()
    try:
        row = await conn.fetchrow(
            "SELECT id, title, description, can_read, can_write, media_types, "
            "created_at FROM taxii_collections WHERE id = $1",
            collection_id,
        )
        return dict(row) if row else None
    finally:
        await conn.close()


async def _get_objects(
    collection_id: str,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Fetch objects from a collection with pagination.

    Returns (objects, total_count).
    """
    conn = await _get_db()
    try:
        count_row = await conn.fetchrow(
            "SELECT COUNT(*) AS cnt FROM taxii_objects WHERE collection_id = $1",
            collection_id,
        )
        total = count_row["cnt"]

        rows = await conn.fetch(
            "SELECT id, type, created, modified, object, date_added "
            "FROM taxii_objects WHERE collection_id = $1 "
            "ORDER BY date_added ASC LIMIT $2 OFFSET $3",
            collection_id, limit, offset,
        )
        return [dict(r) for r in rows], total
    finally:
        await conn.close()


async def _get_manifest(
    collection_id: str,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Fetch manifest entries from a collection with pagination.

    Returns (entries, total_count).
    """
    conn = await _get_db()
    try:
        count_row = await conn.fetchrow(
            "SELECT COUNT(*) AS cnt FROM taxii_objects WHERE collection_id = $1",
            collection_id,
        )
        total = count_row["cnt"]

        rows = await conn.fetch(
            "SELECT id, date_added FROM taxii_objects "
            "WHERE collection_id = $1 "
            "ORDER BY date_added ASC LIMIT $2 OFFSET $3",
            collection_id, limit, offset,
        )
        entries = [
            {
                "id": r["id"],
                "date_added": r["date_added"].strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            }
            for r in rows
        ]
        return entries, total
    finally:
        await conn.close()


async def _get_collection_date_range(
    collection_id: str,
) -> tuple[str | None, str | None]:
    """Get the first and last date_added for a collection's objects."""
    conn = await _get_db()
    try:
        first_row = await conn.fetchrow(
            "SELECT MIN(date_added) AS first FROM taxii_objects "
            "WHERE collection_id = $1",
            collection_id,
        )
        last_row = await conn.fetchrow(
            "SELECT MAX(date_added) AS last FROM taxii_objects "
            "WHERE collection_id = $1",
            collection_id,
        )
        first = first_row["first"].strftime("%Y-%m-%dT%H:%M:%S+00:00") if first_row and first_row["first"] else None
        last = last_row["last"].strftime("%Y-%m-%dT%H:%M:%S+00:00") if last_row and last_row["last"] else None
        return first, last
    finally:
        await conn.close()


async def _insert_objects(collection_id: str, objects: list[dict[str, Any]]) -> int:
    """Insert STIX objects into a collection. Returns count inserted."""
    conn = await _get_db()
    inserted = 0
    try:
        for obj in objects:
            obj_id = obj.get("id", str(uuid.uuid4()))
            obj_type = obj.get("type", "unknown")
            created = obj.get("created")
            modified = obj.get("modified")
            try:
                await conn.execute(
                    """
                    INSERT INTO taxii_objects
                        (id, collection_id, type, created, modified, object)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (id) DO UPDATE SET
                        object = EXCLUDED.object,
                        modified = EXCLUDED.modified
                    """,
                    obj_id, collection_id, obj_type, created, modified,
                    json.dumps(obj, default=str),
                )
                inserted += 1
            except Exception:
                logger.warning("Failed to insert object %s", obj_id)
        return inserted
    finally:
        await conn.close()


# ---------------------------------------------------------------------------
# Startup: ensure tables and seed default collection
# ---------------------------------------------------------------------------

@router.on_event("startup")
async def _taxii_startup() -> None:
    """Initialize TAXII tables on router startup."""
    try:
        await _ensure_tables()
        await _seed_default_collection()
    except Exception as exc:
        logger.warning("TAXII startup init failed (continuing): %s", exc)


# ---------------------------------------------------------------------------
# 4.1 Server Discovery — GET /taxii2/
# ---------------------------------------------------------------------------

@router.get("/")
async def taxii_discovery(
    _user=Depends(require_permission("iocs:read")),
) -> Response:
    """TAXII 2.1 Server Discovery endpoint.

    Returns server title, description, contact, default API root,
    and list of advertised API roots.
    """
    discovery = {
        "title": "ARGUS TAXII Server",
        "description": "ARGUS CTI TAXII 2.1 Server for threat intelligence sharing",
        "contact": "cti@argus.local",
        "default": DEFAULT_API_ROOT,
        "api_roots": [DEFAULT_API_ROOT],
    }
    return _taxii_response(discovery)


# ---------------------------------------------------------------------------
# 4.2 API Root Information — GET /taxii2/api1/
# ---------------------------------------------------------------------------

@router.get("/api1/")
async def api_root_info(
    _user=Depends(require_permission("iocs:read")),
) -> Response:
    """TAXII 2.1 API Root Information endpoint.

    Returns API root title, supported versions, and max content length.
    """
    info = {
        "title": "ARGUS API Root",
        "versions": ["taxii-2.1"],
        "max_content_length": 104857600,  # 100 MB
    }
    return _taxii_response(info)


# ---------------------------------------------------------------------------
# 5.1 Get Collections — GET /taxii2/api1/collections/
# ---------------------------------------------------------------------------

@router.get("/api1/collections/")
async def list_collections(
    _user=Depends(require_permission("iocs:read")),
) -> Response:
    """TAXII 2.1 Get Collections endpoint.

    Returns a list of all available collections.
    """
    collections = await _get_collections()
    return _taxii_response({"collections": collections})


# ---------------------------------------------------------------------------
# 5.2 Get Collection — GET /taxii2/api1/collections/{id}/
# ---------------------------------------------------------------------------

@router.get("/api1/collections/{collection_id}/")
async def get_collection(
    collection_id: str,
    _user=Depends(require_permission("iocs:read")),
) -> Response:
    """TAXII 2.1 Get Collection endpoint.

    Returns details for a specific collection.
    """
    collection = await _get_collection(collection_id)
    if collection is None:
        error = {
            "title": "Collection Not Found",
            "detail": f"Collection '{collection_id}' does not exist",
            "status": "not_found",
        }
        return _taxii_response(error)

    return _taxii_response(collection)


# ---------------------------------------------------------------------------
# 5.3 Get Object Manifest — GET /taxii2/api1/collections/{id}/manifest/
# ---------------------------------------------------------------------------

@router.get("/api1/collections/{collection_id}/manifest/")
async def get_manifest(
    collection_id: str,
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    _user=Depends(require_permission("iocs:read")),
) -> Response:
    """TAXII 2.1 Get Object Manifest endpoint.

    Returns a manifest of objects in the collection with pagination.
    Includes X-TAXII-Date-Added-First and X-TAXII-Date-Added-Last headers.
    """
    # Verify collection exists
    collection = await _get_collection(collection_id)
    if collection is None:
        error = {
            "title": "Collection Not Found",
            "detail": f"Collection '{collection_id}' does not exist",
            "status": "not_found",
        }
        return _taxii_response(error)

    entries, total = await _get_manifest(collection_id, limit, offset)
    manifest: dict[str, Any] = {"objects": entries}

    # Get date range headers
    date_first, date_last = await _get_collection_date_range(collection_id)

    headers = {}
    if date_first:
        headers["X-TAXII-Date-Added-First"] = date_first
    if date_last:
        headers["X-TAXII-Date-Added-Last"] = date_last

    return _taxii_response(manifest, **headers)


# ---------------------------------------------------------------------------
# 5.4 Get Objects — GET /taxii2/api1/collections/{id}/objects/
# ---------------------------------------------------------------------------

@router.get("/api1/collections/{collection_id}/objects/")
async def get_objects(
    collection_id: str,
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    _user=Depends(require_permission("iocs:read")),
) -> Response:
    """TAXII 2.1 Get Objects endpoint.

    Returns a TAXII envelope containing STIX objects from the collection.
    Supports pagination via limit/offset query parameters.
    Includes X-TAXII-Date-Added-First and X-TAXII-Date-Added-Last headers.
    """
    # Verify collection exists
    collection = await _get_collection(collection_id)
    if collection is None:
        error = {
            "title": "Collection Not Found",
            "detail": f"Collection '{collection_id}' does not exist",
            "status": "not_found",
        }
        return _taxii_response(error)

    objects, total = await _get_objects(collection_id, limit, offset)

    # Build envelope
    envelope: dict[str, Any] = {
        "type": "envelope",
        "id": f"envelope--{uuid.uuid4()}",
        "spec_version": "2.1",
    }

    # Only include objects key if there are objects (TAXII spec: optional)
    stix_objects = [obj["object"] for obj in objects]
    envelope["objects"] = stix_objects

    # Pagination: include "more" flag and "next" offset
    next_offset = offset + limit
    if next_offset < total:
        envelope["more"] = True
        envelope["next"] = str(next_offset)

    # Get date range headers
    date_first, date_last = await _get_collection_date_range(collection_id)

    headers = {}
    if date_first:
        headers["X-TAXII-Date-Added-First"] = date_first
    if date_last:
        headers["X-TAXII-Date-Added-Last"] = date_last

    return _taxii_response(envelope, **headers)


# ---------------------------------------------------------------------------
# 5.5 Add Objects — POST /taxii2/api1/collections/{id}/objects/
# ---------------------------------------------------------------------------

@router.post("/api1/collections/{collection_id}/objects/")
async def add_objects(
    collection_id: str,
    payload: dict[str, Any],
    _user=Depends(require_permission("iocs:write")),
) -> Response:
    """TAXII 2.1 Add Objects endpoint.

    Accepts a STIX bundle and adds its objects to the collection.
    Returns the TAXII envelope of accepted objects.
    """
    # Verify collection exists
    collection = await _get_collection(collection_id)
    if collection is None:
        error = {
            "title": "Collection Not Found",
            "detail": f"Collection '{collection_id}' does not exist",
            "status": "not_found",
        }
        return _taxii_response(error)

    # Check write permission on collection
    if not collection.get("can_write", False):
        error = {
            "title": "Write Not Allowed",
            "detail": f"Collection '{collection_id}' is read-only",
            "status": "forbidden",
        }
        return _taxii_response(error)

    # Extract objects from STIX bundle
    objects = payload.get("objects", [])
    if not objects:
        error = {
            "title": "No Objects",
            "detail": "Request body must contain a STIX bundle with 'objects' array",
            "status": "bad_request",
        }
        return _taxii_response(error)

    inserted = await _insert_objects(collection_id, objects)

    logger.info(
        "Added %d objects to collection '%s'", inserted, collection_id,
    )

    # Return envelope of accepted objects
    envelope: dict[str, Any] = {
        "type": "envelope",
        "id": f"envelope--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }

    return _taxii_response(envelope)
