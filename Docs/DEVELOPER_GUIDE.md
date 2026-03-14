# Tribest ASM 개발 가이드

이 문서는 새로 들어온 사람이 현재 프로젝트 구조와 담당 범위를 빠르게 파악하고 바로 작업할 수 있도록 정리한 문서다.

## 1. 시작 전 이해해야 할 것

이 프로젝트는 모듈형으로 작업한다.

- `scanner/` : 스캐너 담당
- `analysis/` : 분석 담당
- `backend/` : API / 저장 / workflow 담당
- `dashboard/` : UI 담당

현재 `integration` 브랜치는 위 모듈들을 로컬 기준으로 한 번 실제로 이어 붙여 본 통합본에 가깝다.

## 2. 기본 실행

```powershell
docker compose up -d --build
```

접속 주소:
- Dashboard: `http://localhost:8501`
- Backend Docs: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

종료:

```powershell
docker compose down
```

## 3. 폴더별 역할

### `scanner/`
스캐너 진입점과 Nmap 실행부가 들어 있다.

주요 파일:
- `scanner/scan.py`
- `scanner/nmap_scan.py`

현재 핵심 포인트:
- `run_scan(target, profile)` 진입점 유지
- 프로필:
  - `quick`
  - `common`
  - `deep`
  - `full`
  - `web`
- `.lab.local` 자산명과 고정 IP 매핑 포함

### `analysis/`
스캔 결과를 기반으로 finding과 score를 만든다.

주요 파일:
- `analysis/analyzer.py`
- `analysis/cve_lookup.py`
- `analysis/kev_lookup.py`
- `analysis/epss_lookup.py`
- `analysis/risk_report.py`

현재 특징:
- rule-based finding 생성
- CVE / KEV / EPSS enrichment
- template / Gemini / Ollama 브리핑 생성

### `backend/`
실제 workflow를 돌리고 결과를 저장/조회한다.

주요 파일:
- `backend/app/main.py`
- `backend/app/storage.py`
- `backend/app/config.py`
- `backend/app/schemas.py`
- `backend/app/services/report_service.py`

현재 특징:
- `POST /api/v1/workflows/run`
- `GET /api/v1/scans/{scan_id}`
- `GET /api/v1/analyses/{scan_id}`
- `GET /api/v1/reports/{scan_id}`
- `POST /api/v1/reports/{scan_id}/regenerate`

### `dashboard/`
사용자 입력과 결과 표시를 담당한다.

주요 파일:
- `dashboard/app.py`

현재 특징:
- 자산 선택 + 직접 입력 + 대기 목록
- 순차 스캔 실행
- 이력 불러오기
- AI 브리핑
- 포트 현황 / 취약점 상세 / Raw 로그 / JSON

## 4. 현재 저장 구조

현재 저장 단위는 `scan_id` 다.

즉 하나의 `scan_id` 아래에:
- scan
- analysis
- report

가 같이 저장된다.

중요:
- 이력 조회는 저장된 report를 그대로 읽는다.
- 현재 AI 엔진 설정에 따라 과거 report 내용을 바꾸면 안 된다.
- AI 재생성이 필요하면 `regenerate` 흐름을 써야 한다.

## 5. 현재 취약 자산

- `OWASP Juice Shop`
- `Apache Tomcat PUT JSP Upload (tomcat/CVE-2017-12615)`
- `Redis Unauthorized Access (redis/4-unacc)`
- `SambaCry (samba/CVE-2017-7494)`
- `MySQL Authentication Bypass (mysql/CVE-2012-2122)`
- `Elasticsearch Groovy Sandbox Escape (elasticsearch/CVE-2015-1427)`
- `vsftpd Backdoor (ftp/CVE-2011-2523)`

## 6. 작업 시 주의

### 스캐너 담당
- 출력 계약을 바꾸지 말 것
- 실패 시 다른 구조의 dict를 반환하지 말고 예외를 raise할 것
- `service.name`, `service.product`, `service.version` 분리를 최대한 정확히 할 것

### 분석 담당
- `severity`, `kind`, `cve_id`, `kev`, `epss` 가 실제로 의미 있게 보이도록 유지
- 현재는 발표 안정성을 위해 오프라인 카탈로그 보강도 같이 사용 중
- 이후 CPE 기반 live lookup으로 확장 예정

### 백엔드 담당
- scan/analysis/report 저장 단위는 `scan_id`
- 조회와 재생성을 섞지 말 것
- 과거 report는 조회 시 변경되지 않아야 함

### 대시보드 담당
- 계산 로직을 UI에 넣지 말 것
- backend 결과를 있는 그대로 보여줄 것
- 이력 불러오기는 저장 결과 조회에 집중할 것

## 7. 다음 확장 포인트

- CPE 기반 NVD live lookup
- drift에 서비스/버전 변화 반영
- evidence / CVSS / 매칭 근거 표시
- 자산 목록 DB화
- batch run / workflow 단위 ID 도입 여부 검토
