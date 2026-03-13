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
    # 단순 포트 추정보다 명시적인 서비스 메타데이터를 우선한다.
    normalized = " ".join(values).strip().lower()
    if "redis" in normalized:
        return "redis"
    if "ssh" in normalized:
        return "ssh"
    # 포트 단독 과분류를 막기 위해 서비스 판별은 텍스트 기반으로 유지한다.
    if "samba" in normalized or "microsoft-ds" in normalized or "netbios-ssn" in normalized or "smb" in normalized:
        return "samba"
    if "ftp" in normalized:
        return "ftp"
    if "mariadb" in normalized:
        return "mariadb"
    if "mysql" in normalized:
        return "mysql"
    if "elasticsearch" in normalized or "opensearch" in normalized:
        return "elasticsearch"
    if "http" in normalized or "nginx" in normalized or "apache" in normalized:
        return "http"
    # 서비스 메타데이터가 완전히 비어 있을 때만 제한적으로 fallback을 허용한다.
    if not normalized and port.port in {80, 443, 8080}:
        return "http"
    return (port.service.name or port.service.product or "").strip().lower()
