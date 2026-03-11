# Analysis Update Notes

이 문서는 `analysis` 모듈의 수정사항 노트입니다.

## 03-12 수정 내역

### analysis/cve_lookup.py
#### 1. offline CVE fallback 오탐 보정
- 버전 prefix가 필요한 offline CVE는 `service.version` 값이 있을 때만 매칭
- 이전에는 버전 식별이 비어 있어도 특정 버전용 CVE가 붙을 수 있었는데 막았음

#### 2. offline catalog 보강
- Samba 4.15 계열 fallback 항목 추가
- 외부 API가 실패하더라도 Samba 쪽은 최소한의 CVE enrichment가 가능

### analysis/tests/test_analyzer.py
####1. 회귀 테스트 추가
- 아래 케이스 추가
  - 버전이 없는 nginx에는 version-scoped offline CVE가 붙지 않음
  - Samba 4.15 서비스는 offline catalog에서 CVE를 찾을 수 있어야 함

## 현재 상태
- `pytest -q analysis/tests` 기준 통과
- 현재 테스트 결과: `6 passed`
- 기존 Redis/SSH 샘플 리스크 점수(`82 / high`)는 유지

## 아직 남아 있는 작업 @권수용, 디스코드 참고
1. `analysis/analyzer.py` rule 매칭 정밀화
2. `analysis/risk_engine.py` 서비스 판별 정밀화
3. negative 테스트 추가

## 관련 파일
- `analysis/analyzer.py`
- `analysis/cve_lookup.py`
- `analysis/kev_lookup.py`
- `analysis/epss_lookup.py`
- `analysis/risk_engine.py`
- `analysis/tests/test_analyzer.py`
