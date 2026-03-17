# 리포트 가이드

현재 리포트는 `analysis/risk_report.py` 를 기준으로 생성된다.

이 모듈은 기본 분석 결과를 받아 아래 요소를 포함한 최종 report JSON을 만든다.
- 스캔 대상 요약
- 포트 / 서비스 스냅샷
- 분석 결과 요약
- 조합 리스크
- drift
- AI 브리핑

## 1. 리포트 구조

현재 report는 대략 아래 정보를 포함한다.

- `report_type`
- `generated_at`
- `scan_id`
- `target`
- `source_contract`
- `input_snapshot`
- `analysis_reference`
- `scoring`
- `findings_breakdown`
- `combination_breakdown`
- `host_context`
- `narrative`

## 2. AI 브리핑 엔진

지원 엔진:
- `template`
- `gemini`
- `ollama`

### 동작 원칙
- workflow 실행 시 기본적으로 report가 생성되어 저장된다.
- 이력 조회는 저장된 report를 그대로 불러온다.
- AI 엔진을 바꿔 다시 생성하고 싶으면 `regenerate` 흐름을 사용한다.

즉:
- 조회 = 저장본
- 재생성 = 명시적 요청

## 3. 현재 narrative 구조

현재 narrative는 아래 요소를 포함한다.

- `backend`
- `model`
- `language`
- `generated`
- `full_briefing`
- `summary`
- `risk_explanation`
- `recommended_action`
- `fallback_reason`
- `raw_response`

### UI에서 보이는 구조
- `🧭 브리핑 요약`
- `📝 브리핑 본문`
- `🔴 위험 분석`
- `🛡️ 대응 방안`

## 4. 생성 방식

### Template
- fallback 또는 기본 브리핑
- 저장된 기본 결과 확인용으로 사용 가능

### Gemini
- API Key 필요
- 기본 모델은 `gemini-3-flash-preview`

### Ollama
- 로컬 Ollama 실행 필요
- backend 컨테이너 기준으로 모델 목록 조회
- 현재는 `/api/tags` 조회를 통해 모델을 읽는다.

## 5. 리포트 저장과 재생성

현재 report 저장 단위는 `scan_id` 다.

즉 하나의 스캔 결과에는:
- scan
- analysis
- report

가 같이 묶여 있다.

### 저장
- workflow 실행 후 report를 생성해 저장

### 조회
- `GET /api/v1/reports/{scan_id}`
- 저장된 report를 그대로 반환

### 재생성
- `POST /api/v1/reports/{scan_id}/regenerate`
- 선택한 AI 엔진 기준으로 다시 생성 후 같은 `scan_id` report를 갱신

## 6. 현재 한계

- 현재는 발표 안정성을 위해 오프라인 enrichment 결과를 우선 안정화한 상태
- 이후 CPE 기반 NVD live lookup이 붙으면 report 근거가 더 정교해질 수 있음
- evidence, CVSS, 매칭 근거 등은 아직 본격 반영 전
