"""Streamlit dashboard for Tribest ASM."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any

import pandas as pd
import requests
import streamlit as st

BACKEND_URL = os.getenv("DASHBOARD_BACKEND_URL", "http://localhost:8000")
RUNNABLE_TARGETS = {
    "web-target": {
        "short_label": "웹",
        "label": "웹 타깃",
        "target": "web.lab.local",
        "target_ip": "172.28.0.10",
        "scan_option": "web",
        "role": "웹 애플리케이션 타깃",
        "expected_ports": "80, 5678",
        "note": "도메인/고정 IP 둘 다 사용 가능",
    },
    "redis-vuln": {
        "short_label": "Redis",
        "label": "Redis 타깃",
        "target": "redis.lab.local",
        "target_ip": "172.28.0.20",
        "scan_option": "redis",
        "role": "Redis 노출 타깃",
        "expected_ports": "22, 6379",
        "note": "SSH + Redis 분석 흐름 확인용",
    },
}
PLANNED_TARGETS = [
    {"컨테이너": "samba-vuln", "역할": "Samba 타깃", "예상 포트": "445", "고정 IP": "172.28.0.30", "상태": "준비 중"},
    {"컨테이너": "ssh-target", "역할": "SSH 타깃", "예상 포트": "22", "고정 IP": "172.28.0.40", "상태": "준비 중"},
    {"컨테이너": "mysql-target", "역할": "MySQL/MariaDB 타깃", "예상 포트": "3306", "고정 IP": "172.28.0.50", "상태": "준비 중"},
    {"컨테이너": "elasticsearch-target", "역할": "Elasticsearch 타깃", "예상 포트": "9200", "고정 IP": "172.28.0.60", "상태": "준비 중"},
    {"컨테이너": "ftp-target", "역할": "FTP 타깃", "예상 포트": "21", "고정 IP": "172.28.0.70", "상태": "준비 중"},
]
SCAN_OPTIONS = {
    "web": "웹 서비스 중심",
    "redis": "Redis 노출 중심",
    "mixed": "혼합 노출",
}

st.set_page_config(page_title="Tribest ASM Dashboard", layout="wide")
st.title("Tribest ASM Dashboard")
st.caption("스캔 실행과 분석 결과 확인을 한 화면에서 처리하는 기본 대시보드")



def fetch_backend_health(base_url: str) -> tuple[bool, str]:
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        response.raise_for_status()
        return True, "정상"
    except Exception:
        return False, "오프라인"



def fetch_recent_scans(base_url: str) -> list[dict[str, str]]:
    try:
        response = requests.get(f"{base_url}/api/v1/scans", timeout=10)
        response.raise_for_status()
        return response.json().get("items", [])
    except Exception:
        return []



def run_demo_workflow(base_url: str, target: str, scan_option: str) -> dict[str, Any]:
    response = requests.post(
        f"{base_url}/api/v1/workflows/demo",
        json={"target": target, "profile": scan_option},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()



def build_service_inventory(scan_result: dict[str, Any]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for item in scan_result.get("scan", {}).get("ports", []):
        service = item.get("service", {})
        rows.append(
            {
                "포트": item.get("port"),
                "프로토콜": item.get("protocol"),
                "서비스": service.get("name"),
                "제품": service.get("product"),
                "버전": service.get("version"),
            }
        )
    return pd.DataFrame(rows)



def build_scan_overview(scan_result: dict[str, Any]) -> pd.DataFrame:
    logs = scan_result.get("scan", {}).get("logs", [])
    return pd.DataFrame(
        [
            {"항목": "스캔 ID", "값": scan_result.get("scan_id", "-")},
            {"항목": "입력값", "값": scan_result.get("target", {}).get("input_value", "-")},
            {"항목": "해결 IP", "값": scan_result.get("target", {}).get("resolved_ip", "-")},
            {"항목": "열린 포트 수", "값": len(scan_result.get("scan", {}).get("ports", []))},
            {"항목": "로그 수", "값": len(logs)},
            {"항목": "스캔 시작 시각", "값": scan_result.get("scan", {}).get("started_at", "-")},
        ]
    )



def build_scan_logs_frame(scan_result: dict[str, Any]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for log_entry in scan_result.get("scan", {}).get("logs", []):
        rows.append(
            {
                "source": log_entry.get("source"),
                "phase": log_entry.get("phase"),
                "command": log_entry.get("command"),
                "return_code": log_entry.get("return_code"),
                "started_at": log_entry.get("started_at"),
                "finished_at": log_entry.get("finished_at"),
            }
        )
    return pd.DataFrame(rows)



def build_severity_frame(vulnerabilities: list[dict[str, Any]]) -> pd.DataFrame:
    counts = Counter(item.get("severity", "info") for item in vulnerabilities)
    order = ["critical", "high", "medium", "low", "info"]
    rows = [{"severity": key, "count": counts[key]} for key in order if counts.get(key)]
    return pd.DataFrame(rows)



def build_result_summary(payloads: list[dict[str, Any]]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for payload in payloads:
        scan_result = payload["scan_result"]
        analysis_result = payload["analysis_result"]
        risk_summary = analysis_result["analysis"]["risk_summary"]
        drift = analysis_result["drift"]
        rows.append(
            {
                "scan_id": analysis_result["scan_id"],
                "타깃": payload.get("ui_target_label", scan_result["target"]["input_value"]),
                "스캔 상태": "completed",
                "분석 상태": "completed",
                "열린 포트 수": len(scan_result["scan"].get("ports", [])),
                "로그 수": len(scan_result["scan"].get("logs", [])),
                "Findings": len(analysis_result["analysis"]["vulnerabilities"]),
                "Risk Score": risk_summary["score"],
                "Grade": risk_summary["grade"],
                "새 포트": ", ".join(map(str, drift["new_ports"])) or "-",
                "닫힌 포트": ", ".join(map(str, drift["closed_ports"])) or "-",
            }
        )
    return pd.DataFrame(rows)



def render_target_rows() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "이름": value["label"],
                "컨테이너": key,
                "도메인": value["target"],
                "고정 IP": value["target_ip"],
                "역할": value["role"],
                "예상 포트": value["expected_ports"],
                "메모": value["note"],
            }
            for key, value in RUNNABLE_TARGETS.items()
        ]
    )



def render_selection_boxes() -> list[str]:
    selected: list[str] = []
    cols = st.columns(len(RUNNABLE_TARGETS))
    for col, (key, config) in zip(cols, RUNNABLE_TARGETS.items()):
        with col:
            checked = st.checkbox(
                config["short_label"],
                value=(key == "web-target"),
                key=f"target_{key}",
                help=f"{config['label']} | {config['target']} | {config['target_ip']}",
            )
            st.caption(config["expected_ports"])
            if checked:
                selected.append(key)
    return selected


backend_url = st.sidebar.text_input("Backend URL", value=BACKEND_URL)
is_backend_ready, health_label = fetch_backend_health(backend_url)
recent_items = fetch_recent_scans(backend_url) if is_backend_ready else []

with st.sidebar:
    sidebar_ops_tab, sidebar_guide_tab = st.tabs(["운영", "추가 개발"])
    with sidebar_ops_tab:
        st.metric("Backend 상태", health_label)
        st.metric("최근 스캔 수", len(recent_items))
        st.markdown("- 현재는 mock 스캐너 기반 데모 흐름")
        st.markdown("- scan -> analysis 를 같은 화면에서 확인")
        st.markdown("- 포트 스캔 로그도 표시 가능하도록 준비")
        st.markdown("- API 문서: `/docs`")
    with sidebar_guide_tab:
        st.markdown("#### 다음 작업")
        st.markdown("- 실제 Nmap 스캐너 연결")
        st.markdown("- DB 기반 자동 drift 비교")
        st.markdown("- 배치 입력과 CIDR 처리")
        st.markdown("- 리포트 다운로드")
        st.markdown("#### 팀 작업 기준")
        st.markdown("- 스캐너는 JSON 계약과 logs 구조 유지")
        st.markdown("- 분석 모듈은 `scan_result -> analysis_result` 유지")
        st.markdown("- 대시보드는 스캔/분석 구분이 보이게 유지")

metric_a, metric_b, metric_c = st.columns(3)
metric_a.metric("실행 가능한 타깃", len(RUNNABLE_TARGETS))
metric_b.metric("준비 중 타깃", len(PLANNED_TARGETS))
metric_c.metric("최근 스캔 수", len(recent_items))

console_tab, target_tab = st.tabs(["스캔 콘솔", "타깃 목록"])

with console_tab:
    st.subheader("실행 입력")
    input_col, note_col = st.columns([1.2, 0.8])

    with input_col:
        input_mode = st.radio("입력 방식", ["실습 타깃 선택", "직접 입력"], horizontal=True)

        manual_target = ""
        manual_scan_option = "web"
        selected_targets: list[str] = []

        if input_mode == "실습 타깃 선택":
            st.dataframe(render_target_rows(), use_container_width=True, hide_index=True)
            st.markdown("#### 실행 대상")
            selected_targets = render_selection_boxes()
            st.caption("체크한 타깃을 순차 실행한다.")
        else:
            manual_input_type = st.radio("웹 타깃 입력 방식", ["도메인", "IP"], horizontal=True)
            default_value = "web.lab.local" if manual_input_type == "도메인" else "172.28.0.10"
            manual_target = st.text_input("웹 타깃 입력값", value=default_value)
            manual_scan_option = st.selectbox(
                "스캔 옵션",
                options=list(SCAN_OPTIONS.keys()),
                format_func=lambda key: SCAN_OPTIONS[key],
            )
            st.caption("직접 입력은 웹 타깃 도메인이나 IP 확인 용도로 먼저 열어 둔 상태다.")

        if st.button("스캔 실행", type="primary", use_container_width=True):
            results: list[dict[str, Any]] = []
            errors: list[str] = []

            if input_mode == "실습 타깃 선택":
                if not selected_targets:
                    st.warning("최소 한 개 이상의 타깃을 선택해야 한다.")
                else:
                    progress = st.progress(0, text="스캔/분석 실행 중")
                    for index, target_name in enumerate(selected_targets, start=1):
                        target_config = RUNNABLE_TARGETS[target_name]
                        try:
                            payload = run_demo_workflow(
                                backend_url,
                                target_config["target"],
                                target_config["scan_option"],
                            )
                            payload["ui_target_label"] = f"{target_config['label']} ({target_config['target_ip']})"
                            payload["ui_target_name"] = target_name
                            results.append(payload)
                        except Exception as exc:
                            errors.append(f"{target_name}: {exc}")
                        progress.progress(index / len(selected_targets), text=f"{target_name} 처리 완료")
            else:
                if not manual_target.strip():
                    st.warning("도메인 또는 IP를 입력해야 한다.")
                else:
                    try:
                        payload = run_demo_workflow(backend_url, manual_target.strip(), manual_scan_option)
                        payload["ui_target_label"] = f"직접 입력 ({manual_target.strip()})"
                        payload["ui_target_name"] = manual_target.strip()
                        results.append(payload)
                    except Exception as exc:
                        errors.append(f"직접 입력: {exc}")

            if results:
                st.session_state["workflow_runs"] = results
                st.success(f"{len(results)}개 작업 실행 완료")
            if errors:
                st.error("일부 실행 실패\n\n" + "\n".join(errors))

    with note_col:
        st.markdown("#### 실행 흐름")
        st.markdown("1. 타깃 선택 또는 직접 입력")
        st.markdown("2. 스캔 실행")
        st.markdown("3. 같은 요청에서 분석까지 수행")
        st.markdown("4. 아래에서 스캔 결과, 스캔 로그, 분석 결과를 확인")

    st.subheader("실행 결과")
    workflow_runs = st.session_state.get("workflow_runs", [])
    if not workflow_runs:
        st.info("아직 실행된 결과가 없다. 위에서 타깃을 고른 뒤 바로 스캔을 실행하면 된다.")
    else:
        summary_frame = build_result_summary(workflow_runs)
        st.dataframe(summary_frame, use_container_width=True, hide_index=True)

        selected_scan_id = st.selectbox(
            "상세 결과 선택",
            options=[payload["analysis_result"]["scan_id"] for payload in workflow_runs],
            format_func=lambda value: next(
                f"{payload.get('ui_target_label', payload['scan_result']['target']['input_value'])} | {value}"
                for payload in workflow_runs
                if payload["analysis_result"]["scan_id"] == value
            ),
        )
        selected_payload = next(
            payload for payload in workflow_runs if payload["analysis_result"]["scan_id"] == selected_scan_id
        )
        scan_result = selected_payload["scan_result"]
        analysis_result = selected_payload["analysis_result"]
        vulnerabilities = analysis_result["analysis"]["vulnerabilities"]
        severity_frame = build_severity_frame(vulnerabilities)
        service_inventory = build_service_inventory(scan_result)
        scan_overview = build_scan_overview(scan_result)
        scan_logs = build_scan_logs_frame(scan_result)
        risk_summary = analysis_result["analysis"]["risk_summary"]

        stage_a, stage_b, stage_c, stage_d, stage_e = st.columns(5)
        stage_a.metric("대상", selected_payload.get("ui_target_label", scan_result["target"]["input_value"]))
        stage_b.metric("스캔 상태", "completed")
        stage_c.metric("분석 상태", "completed")
        stage_d.metric("Findings", len(vulnerabilities))
        stage_e.metric("Risk Score", risk_summary["score"])

        scan_tab, analysis_tab, raw_tab = st.tabs(["스캔 결과", "분석 결과", "원본 JSON"])

        with scan_tab:
            left, right = st.columns([0.9, 1.1])
            with left:
                st.markdown("#### 스캔 개요")
                st.dataframe(scan_overview, use_container_width=True, hide_index=True)
            with right:
                st.markdown("#### 서비스 인벤토리")
                st.dataframe(service_inventory, use_container_width=True, hide_index=True)

            st.markdown("#### 스캔 로그")
            if scan_logs.empty:
                st.caption("표시할 스캔 로그가 없다.")
            else:
                st.dataframe(scan_logs, use_container_width=True, hide_index=True)
                for index, log_entry in enumerate(scan_result.get("scan", {}).get("logs", []), start=1):
                    with st.expander(f"로그 상세 #{index} | {log_entry.get('source', '-')}"):
                        st.code(log_entry.get("stdout", ""), language="text")
                        if log_entry.get("stderr"):
                            st.code(log_entry.get("stderr", ""), language="text")

        with analysis_tab:
            left, right = st.columns([1.2, 0.8])
            with left:
                st.markdown("#### 분석 요약")
                analysis_summary = pd.DataFrame(
                    [
                        {"항목": "분석 상태", "값": "completed"},
                        {"항목": "Risk Grade", "값": risk_summary["grade"]},
                        {"항목": "Risk Score", "값": risk_summary["score"]},
                        {"항목": "Finding 수", "값": len(vulnerabilities)},
                    ]
                )
                st.dataframe(analysis_summary, use_container_width=True, hide_index=True)

                st.markdown("#### 취약점 결과")
                if vulnerabilities:
                    vulnerability_frame = pd.DataFrame(vulnerabilities).rename(
                        columns={
                            "port": "포트",
                            "service_name": "서비스",
                            "title": "제목",
                            "severity": "심각도",
                            "cve_id": "CVE",
                            "kev": "KEV",
                            "epss": "EPSS",
                        }
                    )
                    st.dataframe(vulnerability_frame, use_container_width=True, hide_index=True)
                else:
                    st.caption("표시할 finding 이 없다.")

            with right:
                st.markdown("#### 심각도 분포")
                if not severity_frame.empty:
                    st.bar_chart(severity_frame.set_index("severity"))
                else:
                    st.caption("표시할 차트 데이터가 없다.")

                st.markdown("#### Drift")
                drift_frame = pd.DataFrame(
                    [
                        {"항목": "새로 열린 포트", "값": ", ".join(map(str, analysis_result["drift"]["new_ports"])) or "-"},
                        {"항목": "닫힌 포트", "값": ", ".join(map(str, analysis_result["drift"]["closed_ports"])) or "-"},
                    ]
                )
                st.dataframe(drift_frame, use_container_width=True, hide_index=True)

        with raw_tab:
            raw_workflow_tab, raw_scan_tab, raw_analysis_tab = st.tabs(["Workflow", "Scan", "Analysis"])
            with raw_workflow_tab:
                st.code(json.dumps(selected_payload, indent=2, ensure_ascii=False), language="json")
            with raw_scan_tab:
                st.code(json.dumps(scan_result, indent=2, ensure_ascii=False), language="json")
            with raw_analysis_tab:
                st.code(json.dumps(analysis_result, indent=2, ensure_ascii=False), language="json")

    st.subheader("최근 스캔")
    if recent_items:
        recent_frame = pd.DataFrame(recent_items).rename(
            columns={"scan_id": "Scan ID", "target": "Target", "created_at": "Created At"}
        )
        st.dataframe(recent_frame, use_container_width=True, hide_index=True)
    else:
        st.caption("저장된 스캔 이력이 아직 없거나 백엔드에 연결되지 않았다.")

with target_tab:
    st.subheader("현재 타깃 현황")
    runnable_frame = pd.DataFrame(
        [
            {
                "이름": value["label"],
                "컨테이너": key,
                "도메인": value["target"],
                "고정 IP": value["target_ip"],
                "역할": value["role"],
                "예상 포트": value["expected_ports"],
                "상태": "실행 가능",
            }
            for key, value in RUNNABLE_TARGETS.items()
        ]
    )
    st.markdown("#### 실행 가능한 타깃")
    st.dataframe(runnable_frame, use_container_width=True, hide_index=True)

    st.markdown("#### 준비 중 타깃")
    st.dataframe(pd.DataFrame(PLANNED_TARGETS), use_container_width=True, hide_index=True)

    st.markdown("#### 현재 기준")
    st.markdown("- 스캔 실행과 결과 보기를 한 화면에서 묶는다.")
    st.markdown("- 결과 영역에서 스캔 결과와 분석 결과를 분리해서 보여준다.")
    st.markdown("- 포트 스캔 raw 로그도 함께 표시할 수 있게 구조를 잡아뒀다.")
    st.markdown("- 웹 타깃은 도메인과 IP 입력을 둘 다 지원한다.")
    st.markdown("- 각 실습 컨테이너는 Compose 고정 IP를 기준으로 정리한다.")
    st.markdown("- 선택 가능한 타깃 목록은 현재 코드에 고정돼 있으며, 사용자 설정형은 아직 아니다.")
