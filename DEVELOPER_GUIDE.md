# Tribest ASM 개발 가이드

이 문서는 처음 프로젝트에 들어온 사람이 구조를 빨리 파악하고, 자기 담당 범위에서 바로 작업을 시작할 수 있게 정리한 가이드다.

---

## 1. 먼저 보면 좋은 것

이 프로젝트는 아직 완성본이 아니다. 각 담당자가 자기 모듈을 이어서 개발할 수 있도록 공통 구조를 먼저 잡아둔 상태다.

지금 기준으로는 다음이 준비되어 있다.
- `scanner/` 스캐너 모듈 분리
- `analysis/` 분석 모듈 구현
- `backend/` FastAPI 스캐폴딩과 임시 연동
- `dashboard/` Streamlit 기본 UI
- `docker-compose.yml` 기반 로컬 실습 환경

다만 스캐너는 아직 실제 Nmap 연동 전이고, 현재는 `scanner/mock_scan.py` 를 통해 mock 결과를 반환한다.

---

## 2. 폴더 구조

```text
scanner/
analysis/
backend/
dashboard/
docker-compose.yml
PROJECT_SPEC.md
README.md
```

### `scanner/`
스캐너 전용 폴더다.

주요 파일:
- `scanner/scan.py`: 스캐너 진입점
- `scanner/mock_scan.py`: 현재 mock 구현

### `analysis/`
취약점 분석 모듈 전용 폴더다.

주요 파일:
- `analysis/models.py`: 입력/출력 JSON 스키마
- `analysis/analyzer.py`: 분석 진입점
- `analysis/cve_lookup.py`: NVD 조회
- `analysis/kev_lookup.py`: KEV 조회
- `analysis/epss_lookup.py`: EPSS 조회
- `analysis/risk_engine.py`: 위험도 계산
- `analysis/tests/test_analyzer.py`: 테스트

### `backend/`
FastAPI 백엔드 폴더다.

주요 파일:
- `backend/app/main.py`: API 엔드포인트
- `backend/app/schemas.py`: 요청/응답 스키마
- `backend/app/storage.py`: SQLite 저장소
- `backend/app/services/report_service.py`: 리포트 stub

### `dashboard/`
대시보드 폴더다.

주요 파일:
- `dashboard/app.py`: 메인 UI

---

## 3. 실행 방법

### 준비
- Docker Desktop 설치 및 실행
- 필요하면 Python 3.11+

### 전체 실행
```powershell
docker compose up -d --build
```

### 접속 주소
- Dashboard: `http://localhost:8501`
- Backend Docs: `http://localhost:8000/docs`
- Backend Health: `http://localhost:8000/health`

### 종료
```powershell
docker compose down
```

---

## 4. 지금 컨테이너는 어떻게 잡혀 있나

현재 Compose 기준 컨테이너와 고정 IP는 아래와 같다.
- `backend`: `172.28.0.2`
- `dashboard`: `172.28.0.3`
- `db`: `172.28.0.4`
- `web-target`: `172.28.0.10`
- `redis-vuln`: `172.28.0.20`
- `samba-vuln`: `172.28.0.30`
- `ssh-target`: `172.28.0.40`
- `other-service`: `172.28.0.50`

참고:
- `samba-vuln`, `ssh-target` 은 아직 placeholder 상태다.
- 실습 흐름을 처음 붙일 때는 `redis-vuln` 부터 시작하는 게 가장 수월하다.

---

## 5. 역할별 작업 범위

### 스캐너 담당
할 일:
- 실제 포트 스캔 구현
- 서비스명, 제품명, 버전 추출
- 결과를 계약된 JSON 형태로 반환
- 가능하면 raw 포트 스캔 로그도 함께 남기기

주로 수정할 파일:
- `scanner/scan.py`
- 필요하면 `scanner/mock_scan.py`
- 필요하면 `backend/Dockerfile`
- 필요하면 `backend/requirements.txt`

주의:
- `analysis/` 내부 분석 규칙을 스캐너 쪽에서 건드리지 말 것
- JSON 키 이름을 임의로 바꾸지 말 것
- backend 안에 스캐너 로직을 다시 넣지 말 것

현재 분석 규칙에 맞춰 우선 잘 잡아야 하는 서비스명은 아래와 같다.
- `redis`
- `ssh`
- `samba`, `smb`, `microsoft-ds`, `netbios-ssn`
- `ftp`
- `mysql`, `mariadb`
- `elasticsearch`
- `http`

로그를 남길 때는 아래 구조를 우선 맞추면 된다.
- `scan.logs[].source`
- `scan.logs[].phase`
- `scan.logs[].command`
- `scan.logs[].started_at`
- `scan.logs[].finished_at`
- `scan.logs[].return_code`
- `scan.logs[].stdout`
- `scan.logs[].stderr`

### 분석 담당
할 일:
- 스캔 결과 JSON을 입력받아 취약점 분석
- NVD, KEV, EPSS 기반 보강
- misconfiguration finding 처리
- risk score 계산
- drift 계산

주로 수정할 파일:
- `analysis/analyzer.py`
- `analysis/cve_lookup.py`
- `analysis/kev_lookup.py`
- `analysis/epss_lookup.py`
- `analysis/risk_engine.py`
- `analysis/models.py`
- `analysis/tests/test_analyzer.py`

현재 기본 규칙은 아래 서비스를 기준으로 잡혀 있다.
- Redis
- SSH
- Samba/SMB
- FTP
- MySQL/MariaDB
- Elasticsearch

주의:
- FastAPI 요청/응답 구조를 분석 모듈 쪽에서 멋대로 바꾸지 말 것
- 공격 기능이나 exploit 코드는 넣지 말 것

### 백엔드 담당
할 일:
- 스캔 실행 API 연결
- 분석 실행 API 연결
- 결과 저장 및 조회
- 리포트 생성 흐름 연결

주로 수정할 파일:
- `backend/app/main.py`
- `backend/app/schemas.py`
- `backend/app/storage.py`
- `backend/app/services/report_service.py`

주의:
- 분석 로직을 `backend/` 안에 중복 구현하지 말 것
- 스캐너 로직을 `backend/` 안에 중복 구현하지 말 것
- 분석은 반드시 `analysis.analyzer.analyze(...)` 를 호출할 것
- 스캔은 반드시 `scanner.run_scan(...)` 흐름을 타게 할 것

### 대시보드 담당
할 일:
- 사용자 입력 수집
- API 호출
- 스캔 결과와 분석 결과 시각화
- 타깃 목록, 상태, drift, finding 표시
- 스캔 로그가 있으면 같이 표시

주로 수정할 파일:
- `dashboard/app.py`

주의:
- 분석 규칙을 UI에서 직접 구현하지 말 것
- Streamlit에서 임의 계산으로 위험도를 만들지 말 것

---

## 6. 제일 중요한 규칙: JSON 계약 유지

모든 모듈은 같은 JSON 계약을 기준으로 연결한다.

### 스캔 결과 JSON
```json
{
  "scan_id": "scan-001",
  "target": {
    "input_value": "redis.lab.local",
    "resolved_ip": "172.28.0.20"
  },
  "scan": {
    "started_at": "2026-03-10T21:00:00+09:00",
    "ports": [
      {
        "port": 6379,
        "protocol": "tcp",
        "service": {
          "name": "redis",
          "product": "Redis",
          "version": "4.0.14"
        }
      }
    ],
    "logs": [
      {
        "source": "nmap",
        "phase": "service_detection",
        "command": "nmap -sV redis.lab.local",
        "started_at": "2026-03-10T21:00:00+09:00",
        "finished_at": "2026-03-10T21:00:03+09:00",
        "return_code": 0,
        "stdout": "... raw output ...",
        "stderr": ""
      }
    ]
  }
}
```

### 분석 결과 JSON
```json
{
  "scan_id": "scan-001",
  "analysis": {
    "vulnerabilities": [
      {
        "port": 6379,
        "service_name": "redis",
        "title": "Redis Unauthorized Access",
        "severity": "critical",
        "cve_id": null,
        "kev": false,
        "epss": null
      }
    ],
    "risk_summary": {
      "score": 82,
      "grade": "high"
    }
  },
  "drift": {
    "new_ports": [],
    "closed_ports": []
  }
}
```

이 구조가 깨지면 스캐너, 분석기, 백엔드, 대시보드가 바로 어긋난다. 키 이름이나 중첩 구조는 합의 없이 바꾸지 않는 게 원칙이다.

---

## 7. 지금 API는 어떻게 보면 되나

현재 자주 보는 엔드포인트는 아래와 같다.
- `GET /health`
- `GET /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `GET /api/v1/analyses/{scan_id}`
- `POST /api/v1/scans/run`
- `POST /api/v1/analysis/run`
- `POST /api/v1/workflows/demo`

지금은 `POST /api/v1/workflows/demo` 가 가장 편하다. 스캔과 분석을 한 번에 실행해서 대시보드 데모 흐름을 맞추기 위한 임시 엔드포인트라고 보면 된다.

---

## 8. 처음 들어오면 어디서부터 보면 되나

### 스캐너 담당이면
1. `scanner/scan.py` 확인
2. 현재 mock 반환 구조 파악
3. 실제 스캐너 출력이 같은 JSON 구조로 나오게 구현
4. 서비스명과 로그 구조를 규격에 맞추기
5. Redis 타깃부터 먼저 붙여보기

### 분석 담당이면
1. `analysis/models.py` 로 입력/출력 구조 확인
2. `analysis/analyzer.py` 확인
3. `analysis/tests/test_analyzer.py` 실행
4. Redis, SSH, Samba, FTP, DB, Elasticsearch 규칙부터 검증

### 백엔드 담당이면
1. `backend/app/main.py` 확인
2. `storage.py` 저장 구조 확인
3. 스캔 실행 -> 분석 실행 -> 조회 흐름 파악
4. 필요하면 `/api/v1/workflows/demo` 를 기준으로 실제 흐름 분리

### 대시보드 담당이면
1. `dashboard/app.py` 확인
2. 현재 입력/실행/결과 구조 파악
3. API 응답 JSON이 어디에 표시되는지 확인
4. 시각화는 개선하되 계산 로직은 백엔드/분석 모듈에 남기기

---

## 9. 테스트와 확인 방법

### 분석 모듈 테스트
```powershell
pytest -q analysis/tests
```

### 백엔드 문법 확인
```powershell
python -m compileall backend
```

### 대시보드 문법 확인
```powershell
python -m compileall dashboard
```

### 스캐너 문법 확인
```powershell
python -m compileall scanner
```

### 전체 실행 후 확인
- `http://localhost:8000/health`
- `http://localhost:8000/docs`
- `http://localhost:8501`

---

## 10. 지금 단계의 한계

- 스캐너는 아직 mock 기반이다.
- 타깃 목록은 아직 사용자 설정형이 아니다.
- `samba-vuln`, `ssh-target` 은 실제 취약 서비스가 아니다.
- 리포트는 아직 stub 수준이다.
- DB는 SQLite 중심이다.

정리하면, 지금은 각 모듈을 안정적으로 나눠 개발할 수 있게 뼈대를 잡아둔 단계라고 보면 된다.

---

## 11. 작업하면서 지켜야 할 것

- 담당 범위를 넘는 구조 변경은 먼저 팀과 공유할 것
- JSON 계약은 함부로 바꾸지 말 것
- 스캐너 로직은 `scanner/` 에만 둘 것
- 분석 로직은 `analysis/` 에만 둘 것
- UI에서 임의 계산하지 말 것
- 공격 기능은 구현하지 말 것
- 처음에는 Redis 시나리오 하나를 확실히 붙이고, 그 다음 확장할 것
