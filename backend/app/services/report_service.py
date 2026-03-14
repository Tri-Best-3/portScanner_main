"""Report generation helpers for the backend."""

from __future__ import annotations

import csv
import importlib
import io
import json
import logging
from typing import Any

LOGGER = logging.getLogger(__name__)


def build_report_payload(
    scan_result: dict[str, Any],
    analysis_result: dict[str, Any],
    previous_scan: dict[str, Any] | None = None,
    *,
    narrative_backend: str = "template",
    gemini_api_key: str | None = None,
    gemini_model: str | None = None,
    ollama_base_url: str | None = None,
    ollama_model: str | None = None,
) -> dict[str, Any]:
    """Return the richer report payload when the report module is available."""
    builder = _load_report_builder()
    if builder is None:
        LOGGER.info("report module is not available yet; using analysis payload fallback")
        return analysis_result

    return builder(
        scan_result=scan_result,
        analysis_response=analysis_result,
        previous_scan=previous_scan,
        narrative_backend=narrative_backend,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
        ollama_base_url=ollama_base_url,
        ollama_model=ollama_model,
    )


def build_report_bundle(scan_id: str, payload: dict[str, Any]) -> dict[str, str]:
    """Create lightweight export formats from an analysis or report payload."""
    vulnerabilities = _extract_rows(payload)

    csv_buffer = io.StringIO()
    writer = csv.DictWriter(
        csv_buffer,
        fieldnames=["port", "service_name", "title", "severity", "cve_id", "kev", "epss"],
    )
    writer.writeheader()
    for row in vulnerabilities:
        writer.writerow(
            {
                "port": row.get("port"),
                "service_name": row.get("service_name"),
                "title": row.get("title"),
                "severity": row.get("severity"),
                "cve_id": row.get("cve_id"),
                "kev": row.get("kev"),
                "epss": row.get("epss"),
            }
        )

    html_rows = "".join(
        f"<tr><td>{row.get('port')}</td><td>{row.get('service_name')}</td><td>{row.get('title')}</td><td>{row.get('severity')}</td></tr>"
        for row in vulnerabilities
    )
    html = (
        "<html><body>"
        f"<h1>Report: {scan_id}</h1>"
        "<table border='1'><thead><tr><th>Port</th><th>Service</th><th>Title</th><th>Severity</th></tr></thead>"
        f"<tbody>{html_rows}</tbody></table></body></html>"
    )

    return {
        "json": json.dumps(payload, indent=2, ensure_ascii=False),
        "csv": csv_buffer.getvalue(),
        "html": html,
    }


def _load_report_builder():
    for module_name in ("report.risk_report", "analysis.risk_report"):
        try:
            module = importlib.import_module(module_name)
            return getattr(module, "build_risk_report")
        except (ImportError, AttributeError):
            continue
    return None


def _extract_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if "findings_breakdown" in payload:
        return list(payload.get("findings_breakdown") or [])
    return list(payload.get("analysis", {}).get("vulnerabilities", []) or [])
