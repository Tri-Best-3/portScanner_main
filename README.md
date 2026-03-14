# Tribest ASM

## 실행 방법

### 준비
- Docker Desktop이 설치되어 있고 실행 중이어야 함
- `docker compose` 명령을 사용할 수 있어야 함

### 실행
```powershell
docker compose up -d --build
```

처음 실행할 때는 이미지 다운로드와 빌드 때문에 시간이 조금 걸릴 수 있다.

### 접속 주소
- Dashboard: `http://localhost:8501`
- Backend API Docs: `http://localhost:8000/docs`
- Backend Health: `http://localhost:8000/health`

### 종료
```powershell
docker compose down
```

## 문서
- 프로젝트 스펙: `Docs/PROJECT_SPEC.md`
- 개발 가이드: `Docs/DEVELOPER_GUIDE.md`
- 리포트 가이드: `Docs/REPORT_GUIDE.md`
- 통합 업데이트: `Docs/INTEGRATION_UPDATE.md`

## 폴더 구성
- 스캐너 모듈: `scanner/`
- 분석 모듈: `analysis/`
- 백엔드: `backend/`
- 대시보드: `dashboard/`
