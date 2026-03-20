# Integration Update

기준 브랜치: `integration`

이 문서는 로컬 통합 과정에서 실제로 어떤 수정이 들어갔는지 파일 단위로 빠르게 확인하려는 용도다.

## 1. 통합 방향

이번 통합 브랜치는 아직 메인에 머지되지 않은 개별 feature 브랜치들을 기준으로,
실제로 한 번 끝까지 실행 가능한 상태를 만드는 데 초점을 맞췄다.

즉 단순 merge 결과물이 아니라:
- 스캐너
- 분석
- 리포트
- 대시보드
- 인프라

를 현재 프로젝트 구조에 맞게 다시 맞춘 실행본에 가깝다.

## 2. 주요 수정 영역

### 인프라
- `docker-compose.yml`
  - 실제 취약 POC 자산 기준으로 정리
  - `tribest-asm` 프로젝트명 적용
  - 컨테이너 이름을 `core-*`, `vuln-*` 형태로 정리

### 스캐너
- `scanner/scan.py`
- `scanner/nmap_scan.py`
  - 실제 Nmap 스캔 프로필 적용
  - `.lab.local` 자산 매핑 반영
  - CSV / raw 로그 저장 반영

### 분석
- `analysis/analyzer.py`
- `analysis/cve_lookup.py`
- `analysis/kev_lookup.py`
- `analysis/epss_lookup.py`
- `analysis/risk_report.py`
  - POC 자산에 맞는 finding 보강
  - CVE / KEV / EPSS enrichment 보강
  - AI 브리핑 본문 구조 보강

### 백엔드
- `backend/app/config.py`
- `backend/app/main.py`
- `backend/app/storage.py`
- `backend/app/schemas.py`
- `backend/app/services/report_service.py`
  - `scan_id` 단위 결과 저장 구조 정리
  - workflow run 엔드포인트 정리
  - report 조회와 재생성 분리
  - Ollama 모델 조회 엔드포인트 추가

### 대시보드
- `dashboard/app.py`
  - 자산 선택 / 직접 입력 / 대기 목록 통합
  - 순차 스캔 실행
  - 이력 조회 개선
  - AI 브리핑 / Raw 로그 / JSON 탭 정리
  - 프로필 설명 UI 정리

## 3. 브랜치별 수정 강도

### `feature/risk`
수정 강도: 낮음 ~ 중간
- 핵심 분석 방향은 유지
- 현재 자산과 결과 구조에 맞게 통합 보정 위주 수정

### `feature/scanner`
수정 강도: 중간
- 스캐너 뼈대는 유지
- 프로필, 자산 매핑, 로그 저장, 호출 구조 보정 반영

### `feature/report`
수정 강도: 중간 ~ 높음
- 리포트 로직은 유지
- 저장/조회/재생성 흐름은 현재 프로젝트 기준으로 재정리

### `feature/dashboard`
수정 강도: 높음
- 화면 뼈대는 반영
- 실제 UX와 데이터 흐름은 통합 기준으로 크게 수정

### `backend / compose / 저장 구조`
수정 강도: 대부분 직접 수정
- 실행, 저장, 이력, AI 브리핑, report 흐름은 통합 브랜치에서 직접 정리

## 4. 현재 기준 유의사항

- 이 브랜치는 발표/시연을 위한 실제 실행 통합본 성격이 강하다.
- 현재 CVE enrichment는 live lookup + 오프라인 카탈로그 보강을 함께 사용한다.
- 이후에는 CPE 기반 NVD live lookup으로 확장하는 방향이 맞다.
