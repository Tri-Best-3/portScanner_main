"""Post-processing risk report builder for combination scoring and narrative output.

This module does not replace the existing ``analysis`` contract.
Instead, it consumes the existing scan/analysis outputs and emits a
separate JSON-friendly report focused on:

- finding score breakdown
- service combination bonuses
- host-level concentration bonuses
- narrative-ready evidence
- optional Gemini-generated Korean narrative with template fallback

It intentionally reuses the existing ``risk_engine`` constants and
service normalization helpers so that the report stays aligned with the
main analysis pipeline.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

try:
    from dotenv import load_dotenv

    load_dotenv(override=False)
except Exception:
    pass

# from analysis.analyzer import AnalyzerConfig, analyze
from analysis.models import AnalysisResponse, DriftResult, PortScanResult, ScanResult, VulnerabilityFinding
from analysis.risk_engine import (
    SEVERITY_WEIGHTS,
    SERVICE_COMBO_BONUSES,
    grade_for_score,
    service_name,
    calculate_risk_summary,
)

# 한 호스트에 민감 서비스가 여러 개일 경우 부여하는 추가 보너스
_HOST_DENSITY_BONUSES: tuple[tuple[int, int, str], ...] = (
    (3, 8, "three_or_more_sensitive_services_on_same_host"),
    (4, 12, "four_or_more_sensitive_services_on_same_host"),
)

# 조합 규칙이 왜 위험한지 설명하기 위한 reason code
_SERVICE_REASON_CODES: dict[frozenset[str], str] = {
    frozenset({"redis", "ssh"}): "service_chain_exposure",
    frozenset({"samba", "ssh"}): "remote_access_plus_file_service",
    frozenset({"mysql", "http"}): "database_plus_web_exposure",
    frozenset({"mariadb", "http"}): "database_plus_web_exposure",
    frozenset({"elasticsearch", "ssh"}): "data_service_plus_remote_access",
    frozenset({"ftp", "ssh"}): "plaintext_transfer_plus_remote_access",
}

# narrative priority 표시용 기준
_PRIORITY_BY_SCORE = (
    (90, "critical"),
    (70, "high"),
    (40, "medium"),
    (1, "low"),
    (0, "info"),
)

_DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")


class GeminiUnavailableError(RuntimeError):
    """Raised when Gemini generation cannot be used and fallback is required."""


class NarrativeSchemaError(ValueError):
    """Raised when the model response does not match the expected narrative schema."""


def build_risk_report(
    scan_result: ScanResult | dict[str, Any],
    analysis_response: AnalysisResponse | dict[str, Any],
    previous_scan: Optional[ScanResult | dict[str, Any]] = None,
    *,
    narrative_backend: str = "auto",
    gemini_api_key: Optional[str] = None,
    gemini_model: Optional[str] = None,
) -> dict[str, Any]:
    """Build a narrative-ready combination risk report.

    Parameters
    ----------
    scan_result:
        포트 스캔 결과 원본.
    analysis_response:
        이미 분석된 결과가 있으면 그대로 사용하고, 없으면 직접 analyze 호출.
    previous_scan:
        이전 스캔 결과. 존재하면 main analyzer의 drift 계산에 활용됨.
    analyzer_config:
        analysis_response가 없을 때 analyze()에 넘길 설정.
    narrative_backend:
        ``auto`` (default), ``gemini``, or ``template``.
        ``auto`` uses Gemini if available, otherwise falls back to template text.
    gemini_api_key:
        Optional explicit API key. If omitted, reads ``GEMINI_API_KEY`` from
        environment or .env.
    gemini_model:
        Optional explicit model name. If omitted, reads ``GEMINI_MODEL`` or
        defaults to ``gemini-2.5-flash``.
    """

    current = _ensure_scan_result(scan_result)
    analysis = _ensure_analysis_response(analysis_response)

    ports = list(current.scan.ports)
    deduped_findings = _deduplicate_findings(list(analysis.analysis.vulnerabilities))

    finding_breakdown = [_finding_breakdown_item(finding) for finding in deduped_findings]
    base_score = sum(item["score_breakdown"]["total"] for item in finding_breakdown)

    normalized_services = _normalized_services(ports)
    combo_breakdown = _matched_combo_breakdown(ports, normalized_services)
    combo_bonus_score = sum(item["bonus"] for item in combo_breakdown)

    host_density = _host_density_breakdown(current, normalized_services)
    density_bonus_score = host_density["bonus"]

    final_score = min(base_score + combo_bonus_score + density_bonus_score, 100)
    grade = grade_for_score(final_score)

    # 기존 risk_engine의 요약 점수와 후가공 점수를 같이 남겨 비교 가능하게 둔다.
    existing_summary = calculate_risk_summary(deduped_findings, ports)

    narrative_ready = _build_narrative_inputs(
        current=current,
        normalized_services=normalized_services,
        findings=finding_breakdown,
        combos=combo_breakdown,
        drift=analysis.drift,
        final_score=final_score,
        grade=grade,
    )

    payload = {
        "report_type": "combination_risk_report",
        "generated_at": _utc_now_iso(),
        "scan_id": current.scan_id,
        "target": current.target.to_dict(),
        "source_contract": {
            "scan_contract_version": "current",
            "analysis_contract_version": "current",
        },
        "input_snapshot": {
            "open_ports": sorted(port.port for port in ports),
            "services": normalized_services,
            "port_services": [_port_service_item(port) for port in ports],
        },
        "analysis_reference": {
            "existing_risk_summary": analysis.analysis.risk_summary.to_dict(),
            "existing_risk_summary_recomputed": existing_summary.to_dict(),
            "drift": analysis.drift.to_dict(),
        },
        "scoring": {
            "base_score": min(base_score, 100),
            "combo_bonus_score": combo_bonus_score,
            "host_density_bonus_score": density_bonus_score,
            "final_score": final_score,
            "final_grade": grade,
            "score_note": (
                "base_score in this report is an explainable post-processing sum and may exceed the "
                "main risk engine's capped score before final bounding. final_score is capped at 100."
            ),
        },
        "findings_breakdown": finding_breakdown,
        "combination_breakdown": combo_breakdown,
        "host_context": host_density,
        # "narrative_ready": narrative_ready_output,
    }

    payload["narrative"] = _build_narrative_section(
        # payload,
        narrative_ready,
        backend=narrative_backend,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
    )
    return payload


def write_risk_report(
    output_path: str,
    scan_result: ScanResult | dict[str, Any],
    analysis_response: AnalysisResponse | dict[str, Any],
    previous_scan: Optional[ScanResult | dict[str, Any]] = None,
    *,
    narrative_backend: str = "auto",
    gemini_api_key: Optional[str] = None,
    gemini_model: Optional[str] = None,
) -> dict[str, Any]:
    """Build the report and write it to disk as formatted JSON."""
    payload = build_risk_report(
        scan_result=scan_result,
        analysis_response=analysis_response,
        previous_scan=previous_scan,
        narrative_backend=narrative_backend,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
    )
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    return payload


def _build_narrative_section(
    narrative_ready: dict[str, Any],
    *,
    backend: str = "auto",
    gemini_api_key: Optional[str] = None,
    gemini_model: Optional[str] = None,
) -> dict[str, Any]:
    backend = (backend or "auto").lower()
    effective_key = gemini_api_key or os.getenv("GEMINI_API_KEY")
    effective_model = gemini_model or os.getenv("GEMINI_MODEL") or _DEFAULT_GEMINI_MODEL

    if backend == "template":
        return _generate_narrative_with_template(narrative_ready)

    if backend not in {"auto", "gemini"}:
        template = _generate_narrative_with_template(narrative_ready)
        template.update(
            {
                "backend": "template",
                "model": None,
                "language": "ko",
                "generated": False,
                "fallback_reason": f"unsupported backend: {backend}",
            }
        )
        return template

    try:
        if not effective_key:
            raise GeminiUnavailableError("GEMINI_API_KEY is not set")
        return _generate_narrative_with_gemini(narrative_ready, api_key=effective_key, model=effective_model)
    except Exception as exc:
        template = _generate_narrative_with_template(narrative_ready)
        template.update(
            {
                "backend": "template",
                "model": None,
                "language": "ko",
                "generated": False,
                "fallback_reason": str(exc),
            }
        )
        return template


def _generate_narrative_with_gemini(
    narrative_ready: dict[str, Any],
    *,
    api_key: str,
    model: str,
) -> dict[str, Any]:
    try:
        from google import genai
    except Exception as exc:  # pragma: no cover
        raise GeminiUnavailableError("google-genai package is not installed") from exc

    prompt_input = narrative_ready["llm_ready_prompt_input"]
    prompt = {
        "task": "보안 위험 요약 생성",
        "language": "ko",
        "rules": [
            "반드시 한국어로만 작성할 것.",
            "제공된 facts 밖의 CVE, 공격 단계, 제품 정보는 추측하지 말 것.",
            "summary는 1문장으로 작성할 것.",
            "risk_explanation은 2~4개의 짧은 문장 리스트로 작성할 것.",
            "recommended_action은 2~4개의 짧은 조치 항목 리스트로 작성할 것.",
            "서비스 조합이 왜 위험한지 우선 설명할 것.",
            "facts.drift.new_ports 또는 facts.drift.closed_ports가 비어 있지 않으면, 포트 변화 내용을 최소 1개 이상 설명할 것.",
        ],
        "input": prompt_input,
        "output_schema": {
            "summary": "string",
            "risk_explanation": ["string"],
            "recommended_action": ["string"],
        },
    }

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=model,
        contents=json.dumps(prompt, ensure_ascii=False),
        config={
            "response_mime_type": "application/json",
            "temperature": 0.2,
        },
    )

    text = getattr(response, "text", None)
    if not text:
        raise NarrativeSchemaError("Gemini returned an empty response")

    try:
        parsed = json.loads(text)
    except Exception as exc:
        raise NarrativeSchemaError("Gemini response was not valid JSON") from exc

    if not isinstance(parsed, dict):
        raise NarrativeSchemaError("Gemini response root must be a JSON object")

    summary = parsed.get("summary")
    risk_explanation = parsed.get("risk_explanation")
    recommended_action = parsed.get("recommended_action")

    if not isinstance(summary, str) or not summary.strip():
        raise NarrativeSchemaError("summary must be a non-empty string")
    if not isinstance(risk_explanation, list) or not all(isinstance(x, str) for x in risk_explanation):
        raise NarrativeSchemaError("risk_explanation must be a list of strings")
    if not isinstance(recommended_action, list) or not all(isinstance(x, str) for x in recommended_action):
        raise NarrativeSchemaError("recommended_action must be a list of strings")

    return {
        "backend": "gemini",
        "model": model,
        "language": "ko",
        "generated": True,
        "summary": summary.strip(),
        "risk_explanation": [x.strip() for x in risk_explanation if x and x.strip()][:4],
        "recommended_action": [x.strip() for x in recommended_action if x and x.strip()][:4],
    }


def _generate_narrative_with_template(narrative_ready: dict[str, Any]) -> dict[str, Any]:
    summary_points = narrative_ready.get("summary_points", [])
    attack_path_hints = narrative_ready.get("attack_path_hints", [])
    top_findings = narrative_ready.get("top_risk_findings", [])

    facts = narrative_ready.get("llm_ready_prompt_input", {}).get("facts", {})
    target_info = facts.get("target", {})
    target = target_info.get("resolved_ip") or target_info.get("input_value") or "unknown target"

    services = facts.get("services", [])
    final_score = facts.get("final_score")
    final_grade = facts.get("final_grade")

    drift = facts.get("drift", {}) or {}
    new_ports = drift.get("new_ports", []) or []
    closed_ports = drift.get("closed_ports", []) or []

    risk_explanation: list[str] = []

    if summary_points:
        risk_explanation.extend(summary_points[:2])

    if attack_path_hints:
        risk_explanation.extend(attack_path_hints[:2])

    if new_ports:
        risk_explanation.append(
            f"이전 스캔 대비 새로 열린 포트는 {', '.join(map(str, new_ports))} 입니다."
        )

    if closed_ports:
        risk_explanation.append(
            f"이전 스캔 대비 닫힌 포트는 {', '.join(map(str, closed_ports))} 입니다."
        )

    if not risk_explanation:
        risk_explanation.append("탐지된 서비스 노출 정보를 기반으로 위험도를 평가했습니다.")

    recommended_action: list[str] = []

    if "redis" in services:
        recommended_action.append("Redis 서비스의 외부 노출 여부와 인증 설정을 우선 점검하세요.")
    if "ssh" in services:
        recommended_action.append("SSH 접근 대상을 제한하고 불필요한 외부 노출을 줄이세요.")
    if "samba" in services:
        recommended_action.append("Samba 공유 설정과 익명 접근 허용 여부를 점검하세요.")
    if "elasticsearch" in services:
        recommended_action.append("Elasticsearch의 외부 접근 제한과 인증 구성을 확인하세요.")

    if not recommended_action:
        recommended_action.append("불필요하게 노출된 서비스와 포트를 우선 정리하세요.")

    top_titles = [item.get("title") for item in top_findings if item.get("title")]
    top_titles_text = ", ".join(top_titles[:2]) if top_titles else "주요 노출 서비스"

    summary = (
        f"{target} 대상에서 {top_titles_text} 기반 위험 신호가 확인되었으며, "
        f"최종 조합 위험도는 {final_score}점({final_grade})으로 평가되었습니다."
    )

    return {
        "backend": "template",
        "model": None,
        "language": "ko",
        "generated": True,
        "summary": summary,
        "risk_explanation": risk_explanation[:4],
        "recommended_action": recommended_action[:4],
        "fallback_reason": None,
    }


def _finding_breakdown_item(finding: VulnerabilityFinding) -> dict[str, Any]:
    severity_score = SEVERITY_WEIGHTS.get(finding.severity, 0)
    kev_bonus = 10 if finding.kev else 0
    epss_bonus = _epss_bonus(finding.epss)
    total = severity_score + kev_bonus + epss_bonus

    return {
        "port": finding.port,
        "service_name": finding.service_name,
        "title": finding.title,
        "severity": finding.severity,
        "kind": finding.kind,
        "cve_id": finding.cve_id,
        "kev": finding.kev,
        "epss": finding.epss,
        "match_confidence": finding.match_confidence,
        "score_breakdown": {
            "severity_score": severity_score,
            "kev_bonus": kev_bonus,
            "epss_bonus": epss_bonus,
            "total": total,
        },
        "narrative_hint": _finding_narrative_hint(finding),
    }


def _matched_combo_breakdown(
    ports: Sequence[PortScanResult],
    normalized_services: Sequence[str],
) -> list[dict[str, Any]]:
    service_set = set(normalized_services)
    breakdown: list[dict[str, Any]] = []

    for required_services, bonus, label in SERVICE_COMBO_BONUSES:
        if not required_services.issubset(service_set):
            continue
        matched_ports = [port.port for port in ports if service_name(port) in required_services]
        reason_code = _SERVICE_REASON_CODES.get(frozenset(required_services), "service_exposure_combination")
        breakdown.append(
            {
                "combo_id": "combo-" + "-".join(sorted(required_services)),
                "label": label,
                "services": sorted(required_services),
                "ports": sorted(matched_ports),
                "bonus": bonus,
                "reason_code": reason_code,
                "evidence": [
                    f"service '{service}' detected on at least one open port" for service in sorted(required_services)
                ],
                "narrative_hint": _combo_narrative_hint(sorted(required_services), reason_code),
            }
        )

    return breakdown


def _host_density_breakdown(current: ScanResult, normalized_services: Sequence[str]) -> dict[str, Any]:
    count = len(set(normalized_services))
    applied_bonus = 0
    applied_reason = None
    for threshold, bonus, reason in _HOST_DENSITY_BONUSES:
        if count >= threshold:
            applied_bonus = bonus
            applied_reason = reason

    return {
        "resolved_ip": current.target.resolved_ip,
        "service_count": count,
        "services": sorted(set(normalized_services)),
        "bonus": applied_bonus,
        "reason_code": applied_reason,
        "narrative_hint": (
            "Multiple sensitive services are concentrated on the same host, which increases operational exposure."
            if applied_bonus > 0
            else "No additional host concentration bonus applied."
        ),
    }


def _build_narrative_inputs(
    current: ScanResult,
    normalized_services: Sequence[str],
    findings: Sequence[dict[str, Any]],
    combos: Sequence[dict[str, Any]],
    drift: DriftResult,
    final_score: int,
    grade: str,
) -> dict[str, Any]:
    top_findings = sorted(findings, key=lambda item: item["score_breakdown"]["total"], reverse=True)[:3]
    reason_codes = [item["reason_code"] for item in combos]
    attack_path_hints = [item["narrative_hint"] for item in combos]

    drift_summary: list[str] = []
    if drift.new_ports:
        drift_summary.append(
            f"Newly opened ports compared to the previous scan: {', '.join(map(str, drift.new_ports))}."
        )
    if drift.closed_ports:
        drift_summary.append(
            f"Closed ports compared to the previous scan: {', '.join(map(str, drift.closed_ports))}."
        )

    prompt_facts = {
        "target": current.target.to_dict(),
        "open_ports": sorted(port.port for port in current.scan.ports),
        "services": list(normalized_services),
        "drift": {
            "new_ports": list(drift.new_ports),
            "closed_ports": list(drift.closed_ports),
        },
        "top_findings": [
            {
                "title": item["title"],
                "port": item["port"],
                "severity": item["severity"],
                "score": item["score_breakdown"]["total"],
                "cve_id": item["cve_id"],
                "kev": item["kev"],
                "epss": item["epss"],
            }
            for item in top_findings
        ],
        "matched_combinations": [
            {
                "services": item["services"],
                "ports": item["ports"],
                "reason_code": item["reason_code"],
                "bonus": item["bonus"],
            }
            for item in combos
        ],
        "final_score": final_score,
        "final_grade": grade,
    }

    summary_points = [
        f"Target {current.target.resolved_ip} exposes {len(current.scan.ports)} open ports.",
        f"Detected services: {', '.join(sorted(set(normalized_services)))}.",
        f"Final combination risk score is {final_score} ({grade}).",
        *drift_summary,
    ]

    return {
        "priority": _priority_for_score(final_score),
        "summary_points": summary_points,
        "reason_codes": reason_codes,
        "attack_path_hints": attack_path_hints,
        "top_risk_findings": top_findings,
        "llm_ready_prompt_input": {
            "instruction": (
                "Use only the supplied facts. Explain why the current service combination is risky, "
                "what exposure paths are plausible, what should be prioritized first, "
                "and include any port-open/port-closed changes when drift information is present. "
                "Do not invent CVEs or attack steps that are not present in the facts."
            ),
            "facts": prompt_facts,
        },
    }


# 설명화

def _finding_narrative_hint(finding: VulnerabilityFinding) -> str:
    if finding.kind == "misconfiguration":
        return f"{finding.title} indicates direct service exposure or unsafe configuration on port {finding.port}."
    if finding.cve_id:
        return f"{finding.cve_id} is associated with the service on port {finding.port}."
    return f"Risk signal detected on port {finding.port}."


def _combo_narrative_hint(services: Sequence[str], reason_code: str) -> str:
    joined = " + ".join(services)
    if reason_code == "service_chain_exposure":
        return f"The {joined} combination can increase the chance of chained access on the same host."
    if reason_code == "remote_access_plus_file_service":
        return f"The {joined} combination mixes remote access with file-sharing exposure on one host."
    if reason_code == "database_plus_web_exposure":
        return f"The {joined} combination exposes both application-facing and data-facing surfaces."
    if reason_code == "data_service_plus_remote_access":
        return f"The {joined} combination exposes a data service together with remote administration access."
    if reason_code == "plaintext_transfer_plus_remote_access":
        return f"The {joined} combination mixes plaintext transfer exposure with remote access capability."
    return f"The {joined} combination broadens the exposed attack surface on the same host."


def _normalized_services(ports: Sequence[PortScanResult]) -> list[str]:
    return sorted({service_name(port) for port in ports if service_name(port)})


def _port_service_item(port: PortScanResult) -> dict[str, Any]:
    return {
        "port": port.port,
        "protocol": port.protocol,
        "normalized_service": service_name(port),
        "service": port.service.to_dict(),
    }


def _epss_bonus(value: Optional[float]) -> int:
    if value is None:
        return 0
    if value >= 0.7:
        return 10
    if value >= 0.3:
        return 5
    return 0


def _priority_for_score(score: int) -> str:
    for threshold, label in _PRIORITY_BY_SCORE:
        if score >= threshold:
            return label
    return "info"


# (port, title, cve_id) 가 같으면 동일하다고 가정

def _deduplicate_findings(findings: Sequence[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    deduped: list[VulnerabilityFinding] = []
    seen: set[tuple[int, str, str | None]] = set()
    for finding in findings:
        key = (finding.port, finding.title, finding.cve_id)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _ensure_scan_result(value: ScanResult | dict[str, Any]) -> ScanResult:
    if isinstance(value, ScanResult):
        return value
    return ScanResult(**value)


def _ensure_analysis_response(value: AnalysisResponse | dict[str, Any]) -> AnalysisResponse:
    if isinstance(value, AnalysisResponse):
        return value
    return AnalysisResponse(**value)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
