"""Rule-based risk scoring for vulnerability findings."""

from __future__ import annotations

import logging
from typing import Sequence

from analysis.models import PortScanResult, RiskSummary, VulnerabilityFinding

LOGGER = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "critical": 55,
    "high": 35,
    "medium": 15,
    "low": 5,
    "info": 0,
}


SERVICE_COMBO_BONUSES = (
    ({"redis", "ssh"}, 12, "redis+ssh exposure bonus"),
    ({"samba", "ssh"}, 10, "samba+ssh exposure bonus"),
    ({"mysql", "http"}, 8, "database+web exposure bonus"),
    ({"mariadb", "http"}, 8, "database+web exposure bonus"),
    ({"elasticsearch", "ssh"}, 10, "elasticsearch+ssh exposure bonus"),
    ({"ftp", "ssh"}, 6, "ftp+ssh exposure bonus"),
)


def calculate_risk_summary(
    findings: Sequence[VulnerabilityFinding],
    ports: Sequence[PortScanResult],
) -> RiskSummary:
    score = 0
    seen: set[tuple[int, str, str | None]] = set()
    for finding in findings:
        key = (finding.port, finding.title, finding.cve_id)
        if key in seen:
            continue
        seen.add(key)
        score += SEVERITY_WEIGHTS.get(finding.severity, 0)
        if finding.kev:
            score += 10
        if finding.epss is not None:
            if finding.epss >= 0.7:
                score += 10
            elif finding.epss >= 0.3:
                score += 5

    service_names = {_service_name(port) for port in ports}
    for required_services, bonus, label in SERVICE_COMBO_BONUSES:
        if required_services.issubset(service_names):
            LOGGER.info("Applying %s", label)
            score += bonus

    bounded = min(score, 100)
    return RiskSummary(score=bounded, grade=_grade_for_score(bounded))


def _grade_for_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _service_name(port: PortScanResult) -> str:
    values = [port.service.name or "", port.service.product or ""]
    normalized = " ".join(values).strip().lower()
    if "redis" in normalized:
        return "redis"
    if "ssh" in normalized:
        return "ssh"
    if "samba" in normalized or "microsoft-ds" in normalized or "netbios-ssn" in normalized or port.port in {139, 445}:
        return "samba"
    if "ftp" in normalized or port.port == 21:
        return "ftp"
    if "mysql" in normalized or port.port == 3306:
        return "mysql"
    if "mariadb" in normalized:
        return "mariadb"
    if "elasticsearch" in normalized or "opensearch" in normalized or port.port == 9200:
        return "elasticsearch"
    if "http" in normalized or "nginx" in normalized or "apache" in normalized or port.port in {80, 443, 8080}:
        return "http"
    return (port.service.name or port.service.product or "").strip().lower()

def grade_for_score(score: int) -> str:
    return _grade_for_score(score)

def service_name(port) -> str:
    return _service_name(port)