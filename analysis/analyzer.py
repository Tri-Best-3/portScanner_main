"""High-level vulnerability analysis orchestration."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Optional

import requests

from analysis.cve_lookup import NvdLookupConfig, lookup_cves
from analysis.epss_lookup import EpssLookupConfig, lookup_epss
from analysis.kev_lookup import KevLookupConfig, lookup_kev
from analysis.models import (
    AnalysisBlock,
    AnalysisResponse,
    DriftResult,
    PortScanResult,
    ScanResult,
    VulnerabilityFinding,
)
from analysis.risk_engine import calculate_risk_summary

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class AnalyzerConfig:
    use_live_nvd: bool = False
    use_live_kev: bool = False
    use_live_epss: bool = False
    request_timeout: float = 5.0
    nvd_api_key: str | None = None


@dataclass(frozen=True, slots=True)
class ExposureRule:
    title: str
    severity: str
    aliases: tuple[str, ...]
    ports: tuple[int, ...]
    match_confidence: float
    version_prefixes: tuple[str, ...] = ()


EXPOSURE_RULES: tuple[ExposureRule, ...] = (
    ExposureRule(
        title="Web Application Exposure",
        severity="medium",
        aliases=("http", "https", "nginx", "apache", "tomcat", "jetty", "express", "node", "ppp"),
        ports=(80, 443, 3000, 8080),
        match_confidence=0.80,
    ),
    ExposureRule(
        title="Intentionally Vulnerable Web Application",
        severity="high",
        aliases=("http", "express"),
        ports=(3000,),
        match_confidence=0.88,
    ),
    ExposureRule(
        title="Apache Tomcat PUT JSP Upload Risk",
        severity="high",
        aliases=("tomcat", "apache tomcat", "apache coyote jsp engine"),
        ports=(8080,),
        match_confidence=0.93,
        version_prefixes=("8.5.19",),
    ),
    ExposureRule(
        title="Redis Unauthorized Access",
        severity="critical",
        aliases=("redis",),
        ports=(6379,),
        match_confidence=0.95,
    ),
    ExposureRule(
        title="Redis Replication Abuse RCE Risk",
        severity="critical",
        aliases=("redis",),
        ports=(6379,),
        match_confidence=0.97,
        version_prefixes=("4.0.14",),
    ),
    ExposureRule(
        title="SSH Service Exposure",
        severity="medium",
        aliases=("ssh", "openssh"),
        ports=(22,),
        match_confidence=0.90,
    ),
    # 확장된 서비스 노출 룰: 포트는 신뢰도 보조 사항이고 alias 일치가 필수다.
    ExposureRule(
        title="Samba Service Exposure",
        severity="high",
        aliases=("samba", "smb", "microsoft-ds", "netbios-ssn"),
        ports=(139, 445),
        match_confidence=0.90,
    ),
    ExposureRule(
        title="SambaCry Remote Code Execution Risk",
        severity="critical",
        aliases=("samba", "smb", "netbios-ssn"),
        ports=(445,),
        match_confidence=0.96,
    ),
    ExposureRule(
        title="FTP Plaintext Service Exposure",
        severity="medium",
        aliases=("ftp", "vsftpd", "proftpd", "pure-ftpd"),
        ports=(21,),
        match_confidence=0.85,
    ),
    ExposureRule(
        title="vsftpd Backdoor Risk",
        severity="critical",
        aliases=("ftp", "vsftpd"),
        ports=(21,),
        match_confidence=0.95,
        version_prefixes=("2.3.4",),
    ),
    ExposureRule(
        title="Database Service Exposure",
        severity="high",
        aliases=("mysql", "mariadb"),
        ports=(3306,),
        match_confidence=0.88,
    ),
    ExposureRule(
        title="MySQL Authentication Bypass Risk",
        severity="critical",
        aliases=("mysql",),
        ports=(3306,),
        match_confidence=0.94,
        version_prefixes=("5.5.23",),
    ),
    ExposureRule(
        title="Elasticsearch Unauthorized Access Risk",
        severity="critical",
        aliases=("elasticsearch", "opensearch"),
        ports=(9200,),
        match_confidence=0.92,
    ),
    ExposureRule(
        title="Elasticsearch Groovy Sandbox Escape Risk",
        severity="critical",
        aliases=("elasticsearch",),
        ports=(9200,),
        match_confidence=0.95,
        version_prefixes=("1.4.2",),
    ),
)


class VulnerabilityAnalyzer:
    def __init__(
        self,
        config: Optional[AnalyzerConfig] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.config = config or AnalyzerConfig()
        self.session = session or requests.Session()

    def analyze(
        self,
        scan_result: ScanResult | dict[str, Any],
        previous_scan: Optional[ScanResult | dict[str, Any]] = None,
    ) -> AnalysisResponse:
        current = _ensure_scan_result(scan_result)
        previous = _ensure_scan_result(previous_scan) if previous_scan else None
        findings: list[VulnerabilityFinding] = []

        for port_entry in current.scan.ports:
            findings.extend(self._build_exposure_findings(port_entry))
            findings.extend(self._lookup_cve_findings(port_entry))

        deduped = _deduplicate_findings(findings)
        risk_summary = calculate_risk_summary(deduped, current.scan.ports)
        drift = _calculate_drift(current, previous)
        return AnalysisResponse(
            scan_id=current.scan_id,
            analysis=AnalysisBlock(vulnerabilities=deduped, risk_summary=risk_summary),
            drift=drift,
        )

    def _build_exposure_findings(self, port_entry: PortScanResult) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for rule in EXPOSURE_RULES:
            if _matches_exposure_rule(port_entry, rule):
                findings.append(
                    VulnerabilityFinding(
                        port=port_entry.port,
                        service_name=port_entry.service.name,
                        title=rule.title,
                        severity=rule.severity,
                        kind="misconfiguration",
                        match_confidence=_rule_confidence(port_entry, rule),
                    )
                )
        return findings

    def _lookup_cve_findings(self, port_entry: PortScanResult) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        try:
            candidates = lookup_cves(
                port_entry.service,
                config=NvdLookupConfig(
                    use_live_api=self.config.use_live_nvd,
                    timeout=self.config.request_timeout,
                    api_key=self.config.nvd_api_key,
                ),
                session=self.session,
            )
        except Exception as exc:
            LOGGER.warning("CVE lookup failed for port %s: %s", port_entry.port, exc)
            return findings

        for candidate in candidates:
            enriched = _copy_finding(
                candidate,
                port=port_entry.port,
                service_name=port_entry.service.name,
            )
            try:
                if enriched.cve_id:
                    enriched.kev = lookup_kev(
                        enriched.cve_id,
                        config=KevLookupConfig(
                            use_live_api=self.config.use_live_kev,
                            timeout=self.config.request_timeout,
                        ),
                        session=self.session,
                    )
                    enriched.epss = lookup_epss(
                        enriched.cve_id,
                        config=EpssLookupConfig(
                            use_live_api=self.config.use_live_epss,
                            timeout=self.config.request_timeout,
                        ),
                        session=self.session,
                    )
            except Exception as exc:
                LOGGER.warning("Metadata enrichment failed for %s: %s", enriched.cve_id, exc)
            findings.append(enriched)
        return findings


def analyze(
    scan_result: ScanResult | dict[str, Any],
    previous_scan: Optional[ScanResult | dict[str, Any]] = None,
    config: Optional[AnalyzerConfig] = None,
) -> AnalysisResponse:
    return VulnerabilityAnalyzer(config=config).analyze(scan_result, previous_scan=previous_scan)


def _ensure_scan_result(value: ScanResult | dict[str, Any]) -> ScanResult:
    if isinstance(value, ScanResult):
        return value
    try:
        return ScanResult(**value)
    except Exception as exc:
        LOGGER.exception("Invalid scan payload")
        raise ValueError("Invalid scan payload") from exc


def _calculate_drift(current: ScanResult, previous: Optional[ScanResult]) -> DriftResult:
    if previous is None:
        return DriftResult(new_ports=[], closed_ports=[])
    current_ports = {port.port for port in current.scan.ports}
    previous_ports = {port.port for port in previous.scan.ports}
    return DriftResult(
        new_ports=sorted(current_ports - previous_ports),
        closed_ports=sorted(previous_ports - current_ports),
    )


def _deduplicate_findings(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    deduped: list[VulnerabilityFinding] = []
    seen: set[tuple[int, str, str | None]] = set()
    for finding in findings:
        key = (finding.port, finding.title, finding.cve_id)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return _compress_redundant_findings(deduped)


def _compress_redundant_findings(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    titles_by_port: dict[int, set[str]] = {}
    for finding in findings:
        titles_by_port.setdefault(finding.port, set()).add(finding.title)

    generic_to_specific = {
        "Web Application Exposure": {
            "Apache Tomcat PUT JSP Upload Risk",
            "Intentionally Vulnerable Web Application",
        },
        "Samba Service Exposure": {"SambaCry Remote Code Execution Risk"},
        "Database Service Exposure": {"MySQL Authentication Bypass Risk"},
        "FTP Plaintext Service Exposure": {"vsftpd Backdoor Risk"},
    }

    filtered: list[VulnerabilityFinding] = []
    for finding in findings:
        specific_titles = generic_to_specific.get(finding.title)
        if specific_titles and titles_by_port.get(finding.port, set()).intersection(specific_titles):
            continue
        filtered.append(finding)
    return filtered


def _copy_finding(finding: VulnerabilityFinding, **updates: Any) -> VulnerabilityFinding:
    payload = finding.to_dict()
    payload.update(updates)
    return VulnerabilityFinding(**payload)


def _normalized_service_tokens(port_entry: PortScanResult) -> set[str]:
    tokens: set[str] = set()
    for value in (port_entry.service.name, port_entry.service.product):
        if value:
            normalized = value.strip().lower()
            tokens.add(normalized)
            tokens.update(part for part in normalized.replace("/", " ").replace("-", " ").split() if part)
    return tokens


def _matches_exposure_rule(port_entry: PortScanResult, rule: ExposureRule) -> bool:
    tokens = _normalized_service_tokens(port_entry)
    # service.name / service.product 근거가 있어야 하며, 포트만으로는 finding을 만들지 않는다.
    alias_match = any(alias in tokens for alias in rule.aliases)
    if not alias_match:
        return False
    if not rule.version_prefixes:
        return True
    version = (port_entry.service.version or "").strip().lower()
    if not version:
        return False
    return any(version.startswith(prefix) for prefix in rule.version_prefixes)


def _rule_confidence(port_entry: PortScanResult, rule: ExposureRule) -> float:
    tokens = _normalized_service_tokens(port_entry)
    score = 0.55
    if any(alias in tokens for alias in rule.aliases):
        score += 0.25
    # 포트는 finding 생성 조건이 아니라 confidence 조정용 보조 사항이다.
    if port_entry.port in rule.ports:
        score += 0.15
    if rule.version_prefixes:
        version = (port_entry.service.version or "").strip().lower()
        if any(version.startswith(prefix) for prefix in rule.version_prefixes):
            score += 0.05
    return round(min(score, rule.match_confidence), 2)
