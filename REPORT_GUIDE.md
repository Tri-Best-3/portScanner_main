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
    "resolved_ip": "string",
    "scope_tag": "string | null"
  },
  "source_contract": {
    "analysis_version": "string",
    "uses_existing_analyzer": "boolean",
    "uses_existing_risk_engine": "boolean"
  },
  "input_snapshot": {   # 현재 스캔 요약
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
          "extrainfo": "string | null"
        }
      }
    ]
  },
  "analysis_reference": {   # 기존 분석 결과
    "original_score": "number",
    "original_grade": "string",
    "drift": {
      "new_ports": ["number"],
      "closed_ports": ["number"]
    }
  },
  "scoring": {  # 조합 스코어링 (최종 점수)
    "base_score": "number",
    "combo_bonus_score": "number",
    "host_density_bonus_score": "number",
    "final_score": "number",
    "grade": "string"
  },
  "findings_breakdown": [   # 개별 취약점
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
  "combination_breakdown": [    # 조합이 위험한 이유 정보 
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
  "host_context": {     # 한 호스트에 붙은 민감 서비스 정보 
    "resolved_ip": "string",
    "service_count": "number",
    "services": ["string"],
    "bonus": "number",
    "reason_code": "string",
    "narrative_hint": "string"
  },
  "narrative": {    # 자연어 처리 결과 
    "backend": "string",
    "model": "string | null",
    "language": "string",
    "generated": "boolean",
    "summary": "string",
    "risk_explanation": ["string"],
    "recommended_action": ["string"],
    "fallback_reason": "string | null"
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
    ...
  ],
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
    "summary": "demo.lab.local 서버는 Redis 및 Elasticsearch와 같은 중요한 데이터 서비스가 SSH와 함께 노출되어 있어 무단 접근 및 데이터 유출 위험이 매우 높습니다.",
    "risk_explanation": [
      "Redis (6379)와 Elasticsearch (9200) 같은 중요한 데이터 서비스가 원격 접근 서비스인 SSH (22)와 함께 노출되어 있습니다.",
      "이러한 조합은 공격자가 SSH를 통해 시스템에 접근한 후, 인증되지 않은 Redis 또는 Elasticsearch 인스턴스를 악용하여 민감한 데이터에 접근하거나 시스템을 제어할 수 있는 경로를 제공합니다.",
      "특히 Redis와 Elasticsearch는 무단 접근 위험이 'critical'로 평가되어 데이터 유출 및 서비스 중단의 직접적인 위협이 됩니다."
    ],
    "recommended_action": [
      "Redis 및 Elasticsearch 서비스에 대한 접근 제어를 즉시 강화하고, 불필요한 외부 노출을 제한하십시오.",
      "SSH 서비스에 대한 강력한 인증 정책(예: 키 기반 인증, 2FA)을 적용하고, 불필요한 경우 외부 접근을 제한하십시오.",
      "모든 서비스에 대해 최신 보안 패치를 적용하고, 정기적인 취약점 스캔을 수행하여 추가적인 위험을 식별하십시오."
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