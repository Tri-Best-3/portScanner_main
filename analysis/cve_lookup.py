"""NVD-backed CVE lookup with an offline fallback catalog."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Optional

import requests

from analysis.models import ServiceInfo, VulnerabilityFinding

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class NvdLookupConfig:
    use_live_api: bool = False
    timeout: float = 5.0
    max_results: int = 5
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"


_OFFLINE_CATALOG: list[dict[str, Any]] = [
    {
        "product": "nginx",
        "version_prefix": "1.18",
        "title": "NGINX resolver off-by-one vulnerability",
        "cve_id": "CVE-2021-23017",
        "severity": "high",
        "match_confidence": 0.93,
    },
    {
        "product": "apache http server",
        "version_prefix": "2.4.49",
        "title": "Apache path traversal vulnerability",
        "cve_id": "CVE-2021-41773",
        "severity": "critical",
        "match_confidence": 0.96,
    },
    {
        "product": "samba",
        "version_prefix": "4.15",
        "title": "Samba vfs_fruit heap out-of-bounds vulnerability",
        "cve_id": "CVE-2021-44142",
        "severity": "critical",
        "match_confidence": 0.9,
    },
]


def lookup_cves(
    service: ServiceInfo | dict[str, Any],
    config: Optional[NvdLookupConfig] = None,
    session: Optional[requests.Session] = None,
) -> list[VulnerabilityFinding]:
    normalized = service if isinstance(service, ServiceInfo) else ServiceInfo(**service)
    resolved = config or NvdLookupConfig()
    try:
        if resolved.use_live_api:
            live_results = _lookup_cves_live(normalized, resolved, session)
            if live_results:
                return live_results
    except Exception as exc:
        LOGGER.warning("Falling back to offline CVE catalog for %s: %s", normalized.name, exc)
    return _lookup_cves_offline(normalized)


def _lookup_cves_live(
    service: ServiceInfo,
    config: NvdLookupConfig,
    session: Optional[requests.Session],
) -> list[VulnerabilityFinding]:
    client = session or requests.Session()
    keyword = _build_keyword(service)
    response = client.get(
        config.base_url,
        params={"keywordSearch": keyword, "resultsPerPage": config.max_results},
        timeout=config.timeout,
    )
    response.raise_for_status()
    payload = response.json()
    return _parse_nvd_items(service, payload.get("vulnerabilities", []))


def _lookup_cves_offline(service: ServiceInfo) -> list[VulnerabilityFinding]:
    product = _normalize(service.product or service.name)
    version = (service.version or "").lower()
    findings: list[VulnerabilityFinding] = []
    for entry in _OFFLINE_CATALOG:
        if product != entry["product"]:
            continue
        prefix = entry.get("version_prefix", "")
        if prefix:
            if not version:
                continue
            if not version.startswith(prefix):
                continue
        findings.append(
            VulnerabilityFinding(
                title=entry["title"],
                severity=entry["severity"],
                cve_id=entry["cve_id"],
                match_confidence=entry["match_confidence"],
            )
        )
    return findings


def _parse_nvd_items(service: ServiceInfo, items: list[dict[str, Any]]) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    for item in items:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        description = _extract_description(cve.get("descriptions", []))
        findings.append(
            VulnerabilityFinding(
                title=_build_title(cve_id, description),
                severity=_extract_severity(cve.get("metrics", {})),
                cve_id=cve_id,
                match_confidence=_estimate_match_confidence(service, description),
            )
        )
    return findings


def _build_keyword(service: ServiceInfo) -> str:
    parts = [service.product or service.name, service.version or ""]
    return " ".join(part.strip() for part in parts if part and part.strip())


def _extract_description(descriptions: list[dict[str, Any]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return str(description.get("value", "")).strip()
    return ""


def _build_title(cve_id: str, description: str) -> str:
    if not description:
        return cve_id
    sentence = description.split(". ")[0].strip()
    return sentence[:120] if sentence else cve_id


def _extract_severity(metrics: dict[str, Any]) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        severity = values[0].get("cvssData", {}).get("baseSeverity") or values[0].get("baseSeverity")
        if severity:
            return str(severity).lower()
    return "medium"


def _estimate_match_confidence(service: ServiceInfo, description: str) -> float:
    text = description.lower()
    score = 0.35
    for token in (service.name, service.product, service.version):
        if token and token.lower() in text:
            score += 0.2
    return round(min(score, 0.95), 2)


def _normalize(value: str) -> str:
    return " ".join(value.lower().split())
