"""Scanner module entrypoint.

The backend should call this module instead of keeping scan logic under backend.
When the real scanner is ready, replace the body of ``run_scan`` or route it to the
actual implementation without changing the backend contract.
"""

from __future__ import annotations
from typing import Literal
from scanner.nmap_scanner import run_nmap_scan

# 프로필 타입 정의 (요청에 맞게 mixed 추가 가능)
Profile = Literal["quick", "common", "full", "mixed"]

def run_scan(target: str, profile: Profile = "mixed") -> dict[str, object]:
    """메인 프로젝트 계약에 맞는 JSON을 반환하는 실행 함수"""
    # 실제 nmap 스캔 로직을 호출하여 결과를 반환
    return run_nmap_scan(target, profile=profile)