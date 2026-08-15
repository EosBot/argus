"""Case-scoped evidence exports with ownership and audit enforcement."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.auth.rbac import require_permission
from backend.core.database import get_db
from backend.db.models import AuditLog, Investigation
from backend.export.csv_json_export import CSVJSONExporter
from backend.export.ioc_package import IOCPackageExporter
from backend.export.misp_export import MISPExporter
from backend.export.pdf_report import PDFReportGenerator
from backend.export.sigma_export import SigmaExporter
from backend.export.stix_export import STIXExporter
from backend.export.timeline_export import TimelineExporter
from backend.export.yara_export import YARAExporter

router = APIRouter(prefix="/api/investigations", tags=["exports"])

FORMATS = {"json", "csv", "stix", "misp", "sigma", "yara", "pdf", "timeline", "ioc-package"}


def _safe_filename(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")
    return normalized[:80] or "investigation"


def _data(investigation: Investigation) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    inv = {
        "id": investigation.id,
        "title": investigation.title,
        "description": investigation.description,
        "status": investigation.status,
        "priority": investigation.priority,
        "tags": investigation.tags or [],
        "created_at": investigation.created_at.isoformat(),
        "updated_at": investigation.updated_at.isoformat(),
    }
    findings = [
        {"id": item.id, "title": item.title, "description": item.description, "severity": item.severity, "confidence": item.confidence, "source": item.source, "data": item.data or {}, "created_at": item.created_at.isoformat()}
        for item in investigation.findings
    ]
    iocs = [
        {"id": item.id, "type": item.type, "value": item.value, "threat_type": item.threat_type, "severity": item.severity, "source": item.source, "context": item.context or {}, "created_at": item.created_at.isoformat()}
        for item in investigation.iocs
    ]
    # Raw evidence content is intentionally excluded from general exports.
    evidence = [
        {"id": item.id, "type": item.type, "source_url": item.source_url, "content_hash": item.content_hash, "metadata": item.metadata_ or {}, "created_at": item.created_at.isoformat()}
        for item in investigation.evidence
    ]
    return inv, findings, iocs, evidence


@router.get("/{investigation_id}/export/{export_format}")
async def export_investigation(
    investigation_id: str,
    export_format: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("investigations:read")),
) -> Response:
    fmt = export_format.lower()
    if fmt not in FORMATS:
        raise HTTPException(400, f"Formato inválido. Use: {', '.join(sorted(FORMATS))}")
    investigation = await db.scalar(
        select(Investigation)
        .options(selectinload(Investigation.findings), selectinload(Investigation.iocs), selectinload(Investigation.evidence))
        .where(Investigation.id == investigation_id)
    )
    if investigation is None:
        raise HTTPException(404, "Investigação não encontrada")
    if user.role != "admin" and investigation.owner_id != user.sub:
        raise HTTPException(403, "Esta investigação pertence a outro usuário")

    inv, findings, iocs, evidence = _data(investigation)
    timeline_exporter = TimelineExporter()
    timeline = timeline_exporter.from_investigation(investigation.id, findings, iocs, evidence)
    filename = _safe_filename(investigation.title)

    if fmt == "json":
        payload, media, suffix = CSVJSONExporter().investigation_to_json(inv, findings, iocs, timeline), "application/json", "json"
    elif fmt == "csv":
        payload, media, suffix = CSVJSONExporter().iocs_to_csv(iocs), "text/csv; charset=utf-8", "csv"
    elif fmt == "stix":
        exporter = STIXExporter()
        payload, media, suffix = exporter.to_json(exporter.from_investigation(inv, findings, iocs)), "application/stix+json", "stix.json"
    elif fmt == "misp":
        exporter = MISPExporter()
        payload, media, suffix = exporter.to_json(exporter.from_investigation(inv, findings, iocs)), "application/json", "misp.json"
    elif fmt == "sigma":
        exporter = SigmaExporter()
        payload, media, suffix = exporter.to_yaml_batch(exporter.from_investigation(inv, iocs)), "application/yaml; charset=utf-8", "sigma.yml"
    elif fmt == "yara":
        exporter = YARAExporter()
        payload, media, suffix = exporter.to_rules_batch(exporter.from_investigation(inv, iocs)), "text/plain; charset=utf-8", "yara"
    elif fmt == "pdf":
        payload, media, suffix = PDFReportGenerator().generate(inv, findings, iocs, timeline), "application/pdf", "pdf"
        if not payload.startswith(b"%PDF"):
            raise HTTPException(503, "Exportação PDF indisponível: ReportLab não está instalado no runtime")
    elif fmt == "timeline":
        payload, media, suffix = timeline_exporter.to_json(timeline), "application/json", "timeline.json"
    else:
        exporter = IOCPackageExporter()
        payload, media, suffix = exporter.to_zip(exporter.create_package(inv, findings, iocs)), "application/zip", "ioc-package.zip"

    db.add(AuditLog(user_id=user.sub, action="investigation.export", resource_type="investigation", resource_id=investigation.id, details={"format": fmt, "finding_count": len(findings), "ioc_count": len(iocs), "evidence_count": len(evidence)}))
    content = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    return Response(content=content, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}.{suffix}"', "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})
