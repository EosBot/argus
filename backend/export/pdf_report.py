"""PDF report generation — professional investigation reports.

Generates branded PDF reports with executive summary, findings,
IOCs, timeline, and recommendations. Uses ReportLab for PDF
generation with fallback to HTML-to-PDF.

Usage::

    generator = PDFReportGenerator()
    pdf_bytes = generator.generate(investigation_data, findings, iocs)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _now_str() -> str:
    """Return current UTC time as formatted string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


class PDFReportGenerator:
    """Generates professional PDF investigation reports.

    Produces branded reports with:
        - Cover page with classification marking
        - Executive summary
        - Findings table with severity
        - IOC summary table
        - Timeline visualization
        - Recommendations

    Usage::

        generator = PDFReportGenerator(
            org_name="ACME Security",
            classification="TLP:AMBER",
        )
        pdf_bytes = generator.generate(inv, findings, iocs)
    """

    def __init__(
        self,
        org_name: str = "ARGUS CTI",
        classification: str = "TLP:AMBER",
        logo_path: str | None = None,
    ) -> None:
        """Initialize PDF report generator.

        Args:
            org_name: Organization name for branding.
            classification: TLP classification marking.
            logo_path: Optional path to logo image.
        """
        self.org_name = org_name
        self.classification = classification
        self.logo_path = logo_path

    def generate(
        self,
        investigation: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
        iocs: list[dict[str, Any]] | None = None,
        timeline: list[dict[str, Any]] | None = None,
    ) -> bytes:
        """Generate a PDF report from investigation data.

        Args:
            investigation: Investigation dict with title, description, etc.
            findings: List of finding dicts.
            iocs: List of IOC dicts.
            timeline: Optional list of timeline events.

        Returns:
            PDF document as bytes.
        """
        try:
            return self._generate_with_reportlab(
                investigation, findings, iocs, timeline
            )
        except ImportError:
            logger.warning("ReportLab not available, using HTML fallback")
            return self._generate_html_fallback(
                investigation, findings, iocs, timeline
            )

    def _generate_with_reportlab(
        self,
        investigation: dict[str, Any],
        findings: list[dict[str, Any]] | None,
        iocs: list[dict[str, Any]] | None,
        timeline: list[dict[str, Any]] | None,
    ) -> bytes:
        """Generate PDF using ReportLab.

        Args:
            investigation: Investigation dict.
            findings: List of finding dicts.
            iocs: List of IOC dicts.
            timeline: Optional timeline events.

        Returns:
            PDF document as bytes.
        """
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm, mm
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        from io import BytesIO

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Title"],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor("#1a1a2e"),
        )
        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.HexColor("#16213e"),
        )
        body_style = ParagraphStyle(
            "CustomBody",
            parent=styles["Normal"],
            fontSize=10,
            spaceAfter=6,
        )

        story: list[Any] = []

        # -- Cover Page --
        story.append(Spacer(1, 4 * cm))
        story.append(Paragraph(investigation.get("title", "Investigation Report"), title_style))
        story.append(Spacer(1, 1 * cm))
        story.append(Paragraph(f"<b>Classification:</b> {self.classification}", body_style))
        story.append(Paragraph(f"<b>Organization:</b> {self.org_name}", body_style))
        story.append(Paragraph(f"<b>Generated:</b> {_now_str()}", body_style))
        story.append(Paragraph(f"<b>Investigation ID:</b> {investigation.get('id', 'N/A')}", body_style))
        story.append(PageBreak())

        # -- Executive Summary --
        story.append(Paragraph("Executive Summary", heading_style))
        summary_text = self._build_executive_summary(investigation, findings, iocs)
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 0.5 * cm))

        # -- Findings --
        if findings:
            story.append(Paragraph(f"Findings ({len(findings)})", heading_style))
            findings_data = [["#", "Title", "Severity", "Confidence"]]
            for i, f in enumerate(findings, 1):
                findings_data.append([
                    str(i),
                    f.get("title", "Untitled")[:50],
                    f.get("severity", "info").upper(),
                    f.get("confidence", "medium"),
                ])

            findings_table = Table(findings_data, colWidths=[1 * cm, 8 * cm, 3 * cm, 3 * cm])
            findings_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
                ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#dee2e6")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ]))
            story.append(findings_table)
            story.append(Spacer(1, 0.5 * cm))

        # -- IOCs --
        if iocs:
            story.append(Paragraph(f"Indicators of Compromise ({len(iocs)})", heading_style))
            ioc_data = [["Type", "Value", "Severity"]]
            for ioc in iocs[:100]:  # Limit to 100 IOCs in PDF
                ioc_data.append([
                    ioc.get("type", "unknown"),
                    ioc.get("value", "")[:60],
                    ioc.get("severity", "medium"),
                ])

            ioc_table = Table(ioc_data, colWidths=[3 * cm, 9 * cm, 3 * cm])
            ioc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#dee2e6")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ]))
            story.append(ioc_table)

            if len(iocs) > 100:
                story.append(Paragraph(
                    f"<i>... and {len(iocs) - 100} more IOCs (see full export)</i>",
                    body_style,
                ))

        # -- Timeline --
        if timeline:
            story.append(PageBreak())
            story.append(Paragraph(f"Timeline ({len(timeline)} events)", heading_style))
            for event in timeline[:50]:
                ts = event.get("timestamp", "Unknown")
                title = event.get("title", "Event")
                severity = event.get("severity", "info")
                story.append(Paragraph(
                    f"<b>[{ts}]</b> {title} <i>({severity})</i>",
                    body_style,
                ))

        # -- Footer --
        story.append(PageBreak())
        story.append(Paragraph("Classification", heading_style))
        story.append(Paragraph(
            f"This document is classified <b>{self.classification}</b>. "
            f"Handle according to TLP distribution rules.",
            body_style,
        ))
        story.append(Spacer(1, 1 * cm))
        story.append(Paragraph(
            f"Generated by {self.org_name} — {_now_str()}",
            body_style,
        ))

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    def _generate_html_fallback(
        self,
        investigation: dict[str, Any],
        findings: list[dict[str, Any]] | None,
        iocs: list[dict[str, Any]] | None,
        timeline: list[dict[str, Any]] | None,
    ) -> bytes:
        """Generate HTML report as fallback when ReportLab is unavailable.

        Args:
            investigation: Investigation dict.
            findings: List of finding dicts.
            iocs: List of IOC dicts.
            timeline: Optional timeline events.

        Returns:
            HTML document as bytes.
        """
        html_parts: list[str] = []

        html_parts.append(f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{investigation.get('title', 'Investigation Report')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #16213e; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th {{ background: #16213e; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border: 1px solid #dee2e6; }}
        tr:nth-child(even) {{ background: #f8f9fa; }}
        .classification {{ background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 0.9em; color: #666; }}
    </style>
</head>
<body>
    <h1>{investigation.get('title', 'Investigation Report')}</h1>
    <div class="classification">
        <strong>Classification:</strong> {self.classification}<br>
        <strong>Organization:</strong> {self.org_name}<br>
        <strong>Generated:</strong> {_now_str()}<br>
        <strong>Investigation ID:</strong> {investigation.get('id', 'N/A')}
    </div>
""")

        # Executive Summary
        html_parts.append(f"""
    <h2>Executive Summary</h2>
    <p>{self._build_executive_summary(investigation, findings, iocs)}</p>
""")

        # Findings
        if findings:
            html_parts.append(f"""
    <h2>Findings ({len(findings)})</h2>
    <table>
        <tr><th>#</th><th>Title</th><th>Severity</th><th>Confidence</th></tr>
""")
            for i, f in enumerate(findings, 1):
                html_parts.append(
                    f"        <tr><td>{i}</td><td>{f.get('title', 'Untitled')}</td>"
                    f"<td>{f.get('severity', 'info').upper()}</td>"
                    f"<td>{f.get('confidence', 'medium')}</td></tr>\n"
                )
            html_parts.append("    </table>\n")

        # IOCs
        if iocs:
            html_parts.append(f"""
    <h2>Indicators of Compromise ({len(iocs)})</h2>
    <table>
        <tr><th>Type</th><th>Value</th><th>Severity</th></tr>
""")
            for ioc in iocs[:100]:
                html_parts.append(
                    f"        <tr><td>{ioc.get('type', 'unknown')}</td>"
                    f"<td>{ioc.get('value', '')[:80]}</td>"
                    f"<td>{ioc.get('severity', 'medium')}</td></tr>\n"
                )
            html_parts.append("    </table>\n")

        # Timeline
        if timeline:
            html_parts.append(f"""
    <h2>Timeline ({len(timeline)} events)</h2>
    <table>
        <tr><th>Timestamp</th><th>Event</th><th>Severity</th></tr>
""")
            for event in timeline[:50]:
                html_parts.append(
                    f"        <tr><td>{event.get('timestamp', '')}</td>"
                    f"<td>{event.get('title', '')}</td>"
                    f"<td>{event.get('severity', 'info')}</td></tr>\n"
                )
            html_parts.append("    </table>\n")

        # Footer
        html_parts.append(f"""
    <div class="footer">
        <p>This document is classified <strong>{self.classification}</strong>.
        Handle according to TLP distribution rules.</p>
        <p>Generated by {self.org_name} — {_now_str()}</p>
    </div>
</body>
</html>
""")

        return "".join(html_parts).encode("utf-8")

    @staticmethod
    def _build_executive_summary(
        investigation: dict[str, Any],
        findings: list[dict[str, Any]] | None,
        iocs: list[dict[str, Any]] | None,
    ) -> str:
        """Build executive summary text.

        Args:
            investigation: Investigation dict.
            findings: List of finding dicts.
            iocs: List of IOC dicts.

        Returns:
            Summary text string.
        """
        parts: list[str] = []

        desc = investigation.get("description", "")
        if desc:
            parts.append(desc)

        ioc_count = len(iocs) if iocs else 0
        finding_count = len(findings) if findings else 0

        parts.append(
            f"This investigation identified <b>{ioc_count} IOCs</b> "
            f"across <b>{finding_count} findings</b>."
        )

        # Severity breakdown
        if findings:
            severity_counts: dict[str, int] = {}
            for f in findings:
                sev = f.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            if severity_counts:
                sev_str = ", ".join(
                    f"{count} {level}"
                    for level, count in sorted(severity_counts.items())
                )
                parts.append(f"Findings by severity: {sev_str}.")

        return " ".join(parts)
