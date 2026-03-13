# 리포트 가이드

취약점 조합 스코어링 및 자연어 처리 파트 간단 설명 문서.

---

## 1. risk_report.py

기본 분석 결과를 후가공해 조합 스코어링 결과 + 근거 + 자연어 처리 + 리포트 JSON 생성하는 모듈.

- 조합 스코어링 : `risk_engine.py` 에서 사용하는 항목 재사용
- 조합이 왜 위험한지에 대한 근거 + 자연어 설명 데이터
```
- 어떤 서비스 조합이 매칭되었는지
- 어떤 포트 때문에 조합이 성립했는지
- 조합별 위험 이유
- 자연어 설명(gemini) : 요약/위험 설명/대응 방안
- 이전 스캔 결과와 비교한 포트 변화 감지 문구 (DriftResult 결과 사용)
```

---

## 2. 결과물 JSON
```
{
  "report_type": "string",
  "generated_at": "string",
  "scan_id": "string",
  "target": {
    "input_value": "string",
    "resolved_ip": "string"
  },
  "source_contract": {
    "scan_contract_version": "string",
    "analysis_contract_version": "string"
  },
  "input_snapshot": {
    "open_ports": ["number"],
    "services": ["string"],
    "port_services": [
      {
        "port": "number",
        "protocol": "string",
        "normalized_service": "string",
        "service": {
          "name": "string | null",
          "product": "string | null",
          "version": "string | null",
          "extrainfo": "string | null (optional)"
        }
      }
    ]
  },
  "analysis_reference": {      # 기본 점수 (analyzer가 계산한 값)
    "existing_risk_summary": {
      "score": "number",
      "grade": "string"
    },
    "existing_risk_summary_recomputed": {
      "score": "number",
      "grade": "string"
    },
    "drift": {
      "new_ports": ["number"],
      "closed_ports": ["number"]
    }
  },
  "scoring": {    # 조합 가산점 추가한 최종 점수
    "base_score": "number",
    "combo_bonus_score": "number",
    "host_density_bonus_score": "number",
    "final_score": "number",
    "final_grade": "string",
    "score_note": "string"
  },
  "findings_breakdown": [
    {
      "port": "number",
      "service_name": "string",
      "title": "string",
      "severity": "string",
      "kind": "string",
      "cve_id": "string | null",
      "kev": "boolean",
      "epss": "number | null",
      "match_confidence": "number",
      "score_breakdown": {
        "severity_score": "number",
        "kev_bonus": "number",
        "epss_bonus": "number",
        "total": "number"
      },
      "narrative_hint": "string"
    }
  ],
  "combination_breakdown": [
    {
      "combo_id": "string",
      "label": "string",
      "services": ["string"],
      "ports": ["number"],
      "bonus": "number",
      "reason_code": "string",
      "evidence": ["string"],
      "narrative_hint": "string"
    }
  ],
  "host_context": {
    "resolved_ip": "string",
    "service_count": "number",
    "services": ["string"],
    "bonus": "number",
    "reason_code": "string",
    "narrative_hint": "string"
  },
  "narrative": {
    "backend": "string",
    "model": "string | null",
    "language": "string",
    "generated": "boolean",
    "summary": "string",
    "risk_explanation": ["string"],
    "recommended_action": ["string"],
    "fallback_reason": "string | null (optional)"    # gemini 실패시 들어가는 에러 메세지 / 정상 실행시 안나옴
  }
}

```


`report_sample.json` 확인

- 예시 )
```
...
  "combination_breakdown": [
    {
      "combo_id": "combo-redis-ssh",
      "label": "redis+ssh exposure bonus",
      "services": [
        "redis",
        "ssh"
      ],
      "ports": [
        22,
        6379
      ],
      "bonus": 12,
      "reason_code": "service_chain_exposure",
      "evidence": [
        "service 'redis' detected on at least one open port",
        "service 'ssh' detected on at least one open port"
      ],
      "narrative_hint": "The redis + ssh combination can increase the chance of chained access on the same host."
    },
  "host_context": {
    "resolved_ip": "172.30.0.12",
    "service_count": 3,
    "services": [
      "elasticsearch",
      "redis",
      "ssh"
    ],
    "bonus": 8,
    "reason_code": "three_or_more_sensitive_services_on_same_host",
    "narrative_hint": "Multiple sensitive services are concentrated on the same host, which increases operational exposure."
  },
 ...
  "narrative": {
    "backend": "gemini",
    "model": "gemini-2.5-flash",
    "language": "ko",
    "generated": true,
    "summary": "demo.lab.local은 Redis 및 Elasticsearch의 무단 접근 위험과 SSH 노출이 결합되어 심각한 보안 취약점을 가지고 있습니다.",
    "risk_explanation": [
      "Redis와 Elasticsearch 서비스가 무단 접근 위험에 노출되어 있으며, 여기에 SSH 서비스 노출이 더해져 심각한 보안 위험을 초래합니다.",
      "공격자는 Redis(6379번 포트) 또는 Elasticsearch(9200번 포트)의 무단 접근 취약점을 악용하여 초기 침투를 시도할 수 있습니다.",
      "초기 침투 후, 노출된 SSH 서비스(22번 포트)를 통해 내부 시스템으로의 측면 이동이나 지속적인 접근을 확보하여 피해를 확대할 수 있습니다.",
      "이러한 서비스 조합은 데이터 유출 및 원격 코드 실행으로 이어질 수 있는 명확한 공격 경로를 제공합니다."
    ],
    "recommended_action": [
      "Redis(6379번 포트) 및 Elasticsearch(9200번 포트) 서비스에 대한 인증 및 접근 제어를 즉시 강화하여 무단 접근을 방지하십시오.",
      "SSH 서비스(22번 포트)에 대한 접근을 최소화하고, 강력한 인증(예: 키 기반 인증)을 구현하며, 불필요한 외부 노출을 제한하십시오.",
      "모든 노출된 서비스에 대해 최소 권한 원칙을 적용하고, 방화벽 규칙을 검토하여 외부 접근을 엄격하게 통제하십시오."
    ]
  }
```

---

## 3. 사용법
### API 키 발급

https://aistudio.google.com/api-key

- `.env` 의 **GEMINI_API_KEY** 항목에 추가
`GEMINI_API_KEY=발급받은키`

### 테스트 실행
`python -m analysis.risk_report output.json`

- 루트 폴더에 `output.json` 형태로 생성됨
- 현재 더미 샘플을 입력 값으로 사용하도록 입력되어있는 상태 (추후 분석 결과물로 변경할 예정)

### 실행 안될경우
`requirements.txt` 기준 설치 진행

`pip install -r requirements.txt`

- google-genai==1.66.0
- python-dotenv

항목 설치 필요
