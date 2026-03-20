"""Scanner module entrypoint.

The backend should call this module instead of keeping scan logic under backend.
When the real scanner is ready, replace the body of ``run_scan`` or route it to the
actual implementation without changing the backend contract.
"""

from __future__ import annotations
from typing import Literal

from scanner.nmap_scan import run_nmap_scan

Profile = Literal["quick", "common", "deep", "full", "web"]

def run_scan(target: str, profile: Profile = "common") -> dict[str, object]:
    """메인 프로젝트 계약에 맞는 JSON을 반환하는 실행 함수"""
    return run_nmap_scan(target, profile=profile)

"""Scanner module entrypoint."""

from __future__ import annotations
from typing import Literal
from scanner.nmap_scan import run_nmap_scan, run_inventory_scan

Profile = Literal["quick", "common", "deep", "full", "web"]

def run_scan(target: str, profile: Profile = "common") -> dict[str, object]:
    """기존 단일 타겟 스캔: 상세 리포트 반환용"""
    return run_nmap_scan(target, profile=profile)

def run_inventory_scan(scope: str, profile: Profile = "common") -> dict[str, object]:
    """
    대역/CIDR 스캔: 인벤토리 관리 및 변화(Drift) 감지용
    반환 예시: {"hosts": [{"ip": "...", "status": "up", "open_ports": [...]}, ...]}
    """
    return run_inventory_scan(scope, profile=profile)