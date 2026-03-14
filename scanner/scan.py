"""Scanner module entrypoint.

The backend should call this module instead of keeping scan logic under backend.
When the real scanner is ready, replace the body of ``run_scan`` or route it to the
actual implementation without changing the backend contract.
"""

from __future__ import annotations
from typing import Literal
# 수정됨: nmap_scanner -> nmap_scan (파일명과 일치)
from scanner.nmap_scan import run_nmap_scan

# 프로젝트 기준 프로필 타입 정의
Profile = Literal["quick", "web", "redis", "mixed"]

def run_scan(target: str, profile: Profile = "mixed") -> dict[str, object]:
    """메인 프로젝트 계약에 맞는 JSON을 반환하는 실행 함수"""
    return run_nmap_scan(target, profile=profile)