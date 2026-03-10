"""Report generation stubs for the scaffold."""

from __future__ import annotations

import csv
import io
import json
from typing import Any


def build_report_bundle(scan_id: str, analysis_result: dict[str, Any]) -> dict[str, str]:
    """Create lightweight report outputs from the current analysis result."""
    vulnerabilities = analysis_result.get("analysis", {}).get("vulnerabilities", [])

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
        "json": json.dumps(analysis_result, indent=2, ensure_ascii=False),
        "csv": csv_buffer.getvalue(),
        "html": html,
    }
