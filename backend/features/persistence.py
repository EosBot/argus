"""Investigation persistence — save/load investigations to PostgreSQL.

Stores investigation findings, pipeline metadata, and reports in the
investigations table, linking them to the Investigation ORM model.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import Finding, Investigation

logger = logging.getLogger(__name__)


class InvestigationStore:
    """Persist and retrieve investigation results via SQLAlchemy.

    Stores pipeline findings as Investigation records with linked
    Finding entries for each pipeline stage result.

    Usage::

        store = InvestigationStore(db_session)
        investigation_id = await store.save_investigation(
            title="Phishing campaign",
            findings=orchestrator.get_findings(),
            owner_id=user_id,
        )
        data = await store.get_investigation(investigation_id)
    """

    def __init__(self, db: AsyncSession) -> None:
        """Initialize with an async database session."""
        self._db = db

    async def save_investigation(
        self,
        title: str,
        findings: dict[str, Any],
        owner_id: str,
        description: str | None = None,
        priority: str = "medium",
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Save investigation findings to the database.

        Creates an Investigation record and linked Finding entries
        for each pipeline stage that produced results.

        Args:
            title: Investigation title.
            findings: Consolidated findings dict from the pipeline.
            owner_id: User ID of the investigation owner.
            description: Optional description.
            priority: Priority level (low/medium/high/critical).
            tags: Optional list of tags.
            metadata: Optional metadata dict.

        Returns:
            The created investigation ID.
        """
        investigation_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        investigation = Investigation(
            id=investigation_id,
            title=title,
            description=description,
            status="open",
            priority=priority,
            owner_id=owner_id,
            tags=tags or [],
            metadata_=metadata or {},
        )
        self._db.add(investigation)
        await self._db.flush()

        # Create Finding records for each pipeline stage
        stage_mapping = {
            "iocs": ("IOC Extraction", "info"),
            "geolocation": ("Geolocation & Infrastructure", "info"),
            "links": ("Entity Relationship Analysis", "medium"),
            "temporal": ("Temporal Analysis", "info"),
            "attribution": ("Attribution", "high"),
            "frameworks": ("Analytical Frameworks", "medium"),
            "crypto": ("Cryptocurrency Tracing", "medium"),
        }

        for stage_key, (stage_title, default_severity) in stage_mapping.items():
            stage_data = findings.get(stage_key)
            if not stage_data:
                continue

            finding = Finding(
                id=str(uuid.uuid4()),
                investigation_id=investigation_id,
                title=stage_title,
                description=self._summarize_stage(stage_key, stage_data),
                severity=self._infer_severity(stage_key, stage_data, default_severity),
                confidence="medium",
                source="robin_pipeline",
                data=stage_data if isinstance(stage_data, dict) else {"value": stage_data},
            )
            self._db.add(finding)

        await self._db.flush()
        logger.info(
            "Saved investigation %s with findings from %d stages",
            investigation_id,
            len(findings),
        )
        return investigation_id

    async def get_investigation(self, investigation_id: str) -> dict[str, Any] | None:
        """Retrieve an investigation with its findings.

        Args:
            investigation_id: UUID of the investigation.

        Returns:
            Dict with investigation data and findings, or None if not found.
        """
        result = await self._db.execute(
            select(Investigation).where(Investigation.id == investigation_id),
        )
        investigation = result.scalar_one_or_none()
        if investigation is None:
            return None

        findings_result = await self._db.execute(
            select(Finding).where(Finding.investigation_id == investigation_id),
        )
        findings = findings_result.scalars().all()

        return {
            "id": investigation.id,
            "title": investigation.title,
            "description": investigation.description,
            "status": investigation.status,
            "priority": investigation.priority,
            "owner_id": investigation.owner_id,
            "tags": investigation.tags or [],
            "metadata": investigation.metadata_ or {},
            "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
            "updated_at": investigation.updated_at.isoformat() if investigation.updated_at else None,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "source": f.source,
                    "data": f.data,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                }
                for f in findings
            ],
        }

    async def list_investigations(
        self,
        owner_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List investigations with optional owner filter.

        Args:
            owner_id: Filter by owner user ID.
            limit: Maximum results.
            offset: Pagination offset.

        Returns:
            List of investigation summary dicts.
        """
        query = select(Investigation).order_by(Investigation.created_at.desc())
        if owner_id:
            query = query.where(Investigation.owner_id == owner_id)
        query = query.limit(limit).offset(offset)

        result = await self._db.execute(query)
        investigations = result.scalars().all()

        return [
            {
                "id": inv.id,
                "title": inv.title,
                "status": inv.status,
                "priority": inv.priority,
                "owner_id": inv.owner_id,
                "created_at": inv.created_at.isoformat() if inv.created_at else None,
            }
            for inv in investigations
        ]

    async def delete_investigation(self, investigation_id: str) -> bool:
        """Delete an investigation and its findings (cascade).

        Args:
            investigation_id: UUID of the investigation.

        Returns:
            True if deleted, False if not found.
        """
        result = await self._db.execute(
            select(Investigation).where(Investigation.id == investigation_id),
        )
        investigation = result.scalar_one_or_none()
        if investigation is None:
            return False

        await self._db.delete(investigation)
        await self._db.flush()
        logger.info("Deleted investigation %s", investigation_id)
        return True

    @staticmethod
    def _summarize_stage(stage_key: str, data: Any) -> str:
        """Generate a human-readable summary for a pipeline stage."""
        if stage_key == "iocs":
            count = sum(len(v) for v in data.values() if isinstance(v, list))
            return f"Extracted {count} indicators of compromise"
        if stage_key == "geolocation":
            return f"Geolocated {len(data)} infrastructure indicators"
        if stage_key == "links":
            node_count = data.get("node_count", 0)
            edge_count = data.get("edge_count", 0)
            return f"Entity graph: {node_count} nodes, {edge_count} edges"
        if stage_key == "temporal":
            anomaly_count = data.get("anomaly_count", 0)
            return f"Temporal analysis with {anomaly_count} anomalies detected"
        if stage_key == "attribution":
            verdict = data.get("verdict", "Unknown")
            confidence = data.get("confidence", 0)
            return f"Attribution: {verdict} (confidence: {confidence:.0%})"
        if stage_key == "frameworks":
            technique_count = data.get("technique_count", 0)
            return f"Mapped {technique_count} MITRE ATT&CK techniques"
        if stage_key == "crypto":
            wallet_count = len(data) if isinstance(data, dict) else 0
            return f"Traced {wallet_count} cryptocurrency wallets"
        return f"Pipeline stage '{stage_key}' completed"

    @staticmethod
    def _infer_severity(stage_key: str, data: Any, default: str) -> str:
        """Infer finding severity from stage data."""
        if stage_key == "attribution":
            confidence = data.get("confidence", 0)
            if confidence and confidence > 0.7:
                return "critical"
            if confidence and confidence > 0.4:
                return "high"
        if stage_key == "iocs":
            cves = data.get("cves", []) if isinstance(data, dict) else []
            if cves:
                return "high"
        if stage_key == "temporal":
            anomaly_count = data.get("anomaly_count", 0)
            if anomaly_count and anomaly_count > 5:
                return "high"
        return default
