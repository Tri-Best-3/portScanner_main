import streamlit as st
import pandas as pd
import requests
from datetime import datetime, timedelta

KST_OFFSET = timedelta(hours=9)

st.set_page_config(page_title="Tribest ASM Dashboard", layout="wide")

if "last_scan_data" not in st.session_state:
    st.session_state["last_scan_data"] = None


def convert_to_kst(raw_time_str, fmt="%Y-%m-%d %H:%M:%S"):
    if not raw_time_str:
        return "N/A"
    try:
        clean_str = raw_time_str.replace("T", " ").replace("Z", "")[:19]
        dt_utc = datetime.strptime(clean_str, "%Y-%m-%d %H:%M:%S")
        dt_kst = dt_utc + KST_OFFSET
        return dt_kst.strftime(fmt)
    except Exception:
        return str(raw_time_str)


def get_all_scans(url):
    try:
        res = requests.get(f"{url}/api/v1/scans", timeout=2)
        if res.status_code == 200:
            data = res.json()
            items = data.get("items", []) if isinstance(data, dict) else data
            return sorted(items, key=lambda x: str(x.get("created_at", "")), reverse=True)
        return []
    except Exception:
        return []


def get_scan_detail(url, scan_id):
    try:
        scan_res = requests.get(f"{url}/api/v1/scans/{scan_id}", timeout=5).json()
        analysis_res = requests.get(f"{url}/api/v1/analyses/{scan_id}", timeout=5).json()
        report_res = requests.get(f"{url}/api/v1/reports/{scan_id}", timeout=5)
        report_payload = report_res.json() if report_res.status_code == 200 else {}
        return {
            "scan_result": scan_res,
            "analysis_result": analysis_res,
            "report_result": report_payload,
        }
    except Exception:
        return None


def render_dashboard(data):
    if not data:
        return
    scan_res = data.get("scan_result", {})
    analysis_res = data.get("analysis_result", {})
    report_res = data.get("report_result", {})
    drift_info = analysis_res.get("drift", {})

    st.divider()

    new_p = drift_info.get("new_ports", [])
    closed_p = drift_info.get("closed_ports", [])
    if new_p or closed_p:
        st.error("⚠️ 인프라 변화 감지 (Drift Detected)")
        c_d1, c_d2 = st.columns(2)
        if new_p:
            c_d1.warning(f"🆕 새 포트: {new_p}")
        if closed_p:
            c_d2.info(f"🚫 닫힌 포트: {closed_p}")
    else:
        st.success("✅ 포트 변화 없음")

    r_info = analysis_res.get("analysis", {}).get("risk_summary", {})
    vulns = analysis_res.get("analysis", {}).get("vulnerabilities", [])

    col1, col2, col3 = st.columns(3)
    col1.metric("위험 점수", f"{r_info.get('score', 0)}점")
    col2.metric("등급", r_info.get("grade", "N/A"))
    col3.metric("취약점 수", f"{len(vulns)}개")

    t_ai, t_ports, t_vulns, t_logs = st.tabs(["🤖 AI 브리핑", "🌐 포트 현황", "🚨 취약점 상세", "📝 Raw 로그"])

    with t_ai:
        narrative = report_res.get("narrative", {})
        combo_data = report_res.get("combination_breakdown", [])
        host_context = report_res.get("host_context", {})

        if narrative and (narrative.get("generated") or narrative.get("backend") == "template"):
            st.info(narrative.get("summary", ""))
            ca1, ca2 = st.columns(2)
            with ca1:
                st.write("**🔴 위험 분석**")
                for reason in narrative.get("risk_explanation", []):
                    st.write(f"- {reason}")
            with ca2:
                st.write("**🛡️ 대응 방안**")
                for action in narrative.get("recommended_action", []):
                    st.write(f"- {action}")
        else:
            st.warning("🤖 AI 리포트 생성 대기 중입니다. (분석 완료 후 반영 예정)")

        if combo_data or host_context:
            st.divider()
            if host_context:
                st.write(f"호스트 가점: +{host_context.get('bonus', 0)}")
                st.caption(host_context.get("narrative_hint", ""))
            for combo in combo_data:
                with st.expander(f"위험 조합: {combo.get('label', 'unknown')}"):
                    st.write(f"서비스: {', '.join(combo.get('services', []))}")
                    st.write(f"포트: {', '.join(map(str, combo.get('ports', [])))}")
                    for evidence in combo.get("evidence", []):
                        st.write(f"- {evidence}")

    with t_ports:
        p_list = scan_res.get("scan", {}).get("ports", [])
        if p_list:
            df = pd.DataFrame([
                {"포트": p["port"], "서비스": p["service"]["name"], "제품": p["service"].get("product"), "버전": p["service"].get("version")}
                for p in p_list
            ])
            st.dataframe(df, use_container_width=True, hide_index=True)

    with t_vulns:
        if vulns:
            st.dataframe(pd.DataFrame(vulns), use_container_width=True, hide_index=True)
        else:
            st.success("발견된 취약점이 없습니다.")

    with t_logs:
        for log in scan_res.get("scan", {}).get("logs", []):
            st.caption(f"Source: {log.get('source')} | Cmd: {log.get('command')}")
            st.code(log.get("stdout"))


backend_url = st.sidebar.text_input("Backend URL", value="http://backend:8000")
scans_list = get_all_scans(backend_url)
st.sidebar.metric("누적 스캔", len(scans_list))

st.sidebar.subheader("📜 스캔 이력")
if scans_list:
    history = {}
    for s in scans_list:
        sid = s.get("scan_id") or s.get("id")
        label = f"[{convert_to_kst(s.get('created_at'), '%m/%d %H:%M')}] {s.get('target')}"
        history[label] = sid
    sel_label = st.sidebar.selectbox("기록 선택", list(history.keys()))
    if st.sidebar.button("불러오기", use_container_width=True):
        st.session_state["last_scan_data"] = get_scan_detail(backend_url, history[sel_label])
        st.rerun()

st.title("Tribest ASM Dashboard")

with st.expander("🚀 스캔 실행", expanded=True):
    mode = st.radio("방식", ("자산 선택", "직접 입력"), horizontal=True)
    targets_to_run = []

    if mode == "자산 선택":
        c1, c2 = st.columns(2)
        if c1.checkbox("웹 타깃 (web.lab.local)"):
            targets_to_run.append("web.lab.local")
        if c2.checkbox("Redis 타깃 (redis.lab.local)"):
            targets_to_run.append("redis.lab.local")
    else:
        manual = st.text_input("타겟 입력")
        if manual:
            targets_to_run.append(manual)

    if st.button("스캔 시작", type="primary", use_container_width=True):
        if not targets_to_run:
            st.warning("타겟을 선택하세요.")
        else:
            for target in targets_to_run:
                with st.spinner(f"[{target}] 분석 중..."):
                    try:
                        res = requests.post(
                            f"{backend_url}/api/v1/workflows/demo",
                            json={"target": target},
                            timeout=300,
                        )
                        if res.status_code == 200:
                            st.session_state["last_scan_data"] = get_scan_detail(backend_url, res.json()["scan_result"]["scan_id"])
                            st.success(f"✅ {target} 완료")
                        else:
                            st.error(f"❌ {target} 실패")
                    except Exception as e:
                        st.error(f"Error: {e}")
            st.rerun()

if st.session_state["last_scan_data"]:
    render_dashboard(st.session_state["last_scan_data"])
