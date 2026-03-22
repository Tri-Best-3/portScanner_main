from __future__ import annotations

import nmap
from datetime import datetime, timezone
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed

# 스캔 프로필 설정
PROFILE_CONFIG = {
    "common": {"ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,3306,3389,8080", "args": "-sV -T4"},
    "quick": {"ports": "80,443,22", "args": "-F -T5"},
    "full": {"ports": "1-65535", "args": "-sV -T4"},
    "redis": {"ports": "6379,22", "args": "-sV"},
    "web": {"ports": "80,443,8080,8443", "args": "-sV"}
}

def scan_single_host(ip: str, profile: str = "common") -> dict[str, object]:
    """단일 호스트 상세 포트 스캔 (병렬 작업 단위)"""
    config = PROFILE_CONFIG.get(profile, PROFILE_CONFIG["common"])
    nm = nmap.PortScanner()
    
    try:
        # -Pn: Discovery 생략(이미 살아있음을 확인했으므로), 빠른 포트 스캔
        nm.scan(ip, config["ports"], f"{config['args']} -Pn")
        
        if ip not in nm.all_hosts():
            return {"ip": ip, "status": "down", "open_ports": []}

        open_ports = []
        for proto in nm[ip].all_protocols():
            lport = nm[ip][proto].keys()
            for port in sorted(lport):
                if nm[ip][proto][port]["state"] == "open":
                    open_ports.append(int(port))
        
        return {
            "ip": ip,
            "status": "up",
            "open_ports": open_ports
        }
    except Exception as e:
        return {"ip": ip, "status": "error", "open_ports": [], "error_msg": str(e)}

def run_inventory_scan(scope: str, profile: str = "common", max_workers: int = 50) -> dict[str, object]:
    """
    대역 스캔 구현 (CIDR, Range 지원)
    1. Host Discovery (-sn) 수행
    2. 활성 Host 대상 병렬 포트 스캔
    """
    nm = nmap.PortScanner()
    
    # 1단계: Host Discovery (어떤 IP가 살아있는지 확인)
    # Nmap은 내부적으로 CIDR(192.168.0.0/24) 및 Range(10.0.0.1-20)를 지원함
    nm.scan(hosts=scope, arguments="-sn")
    live_hosts = nm.all_hosts()
    
    results = []
    
    # 2단계: ThreadPoolExecutor를 통한 병렬 포트 스캔
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(scan_single_host, ip, profile): ip for ip in live_hosts}
        
        for future in as_completed(future_to_ip):
            try:
                data = future.result()
                results.append(data)
            except Exception:
                ip = future_to_ip[future]
                results.append({"ip": ip, "status": "error", "open_ports": []})

    # 요구사항에 따른 반환 구조 (IP 순 정렬)
    return {
        "hosts": sorted(results, key=lambda x: x["ip"])
    }

def run_nmap_scan(target: str, profile: str = "common") -> dict[str, object]:
    """기존 단일 타겟 스캔 유지용"""
    started_at = datetime.now(timezone.utc).astimezone()
    res = scan_single_host(target, profile)
    
    # 기존 상세 로그 포맷 유지 (필요시)
    return {
        "scan_id": f"scan-{uuid4().hex[:8]}",
        "target": {"input_value": target, "resolved_ip": res["ip"]},
        "scan": {
            "started_at": started_at.isoformat(),
            "status": res["status"],
            "open_ports": res["open_ports"]
        }
    }