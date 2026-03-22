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
    """단일 호스트 상세 스캔 (서비스 정보 포함)"""
    config = PROFILE_CONFIG.get(profile, PROFILE_CONFIG["common"])
    nm = nmap.PortScanner()
    
    try:
        # -Pn: Ping 생략 (방화벽 우회 및 속도), -sV: 서비스 버전 탐지
        arguments = f"{config.get('args', '-sV')} -Pn"
        nm.scan(ip, config["ports"], arguments)
        
        if ip not in nm.all_hosts():
            return {"ip": ip, "status": "down", "ports": [], "open_ports": []}

        detailed_ports = []
        raw_open_ports = []
        
        for proto in nm[ip].all_protocols():
            lport = nm[ip][proto].keys()
            for port in sorted(lport):
                if nm[ip][proto][port]["state"] == "open":
                    p_info = nm[ip][proto][port]
                    port_int = int(port)
                    raw_open_ports.append(port_int)
                    detailed_ports.append({
                        "port": port_int,
                        "protocol": proto,
                        "service": {
                            "name": p_info.get("name", "unknown"),
                            "product": p_info.get("product", ""),
                            "version": p_info.get("version", "")
                        }
                    })
        
        return {
            "ip": ip,
            "status": "up",
            "ports": detailed_ports,
            "open_ports": raw_open_ports
        }
    except Exception:
        return {"ip": ip, "status": "error", "ports": [], "open_ports": []}

def run_inventory_scan(scope: str, profile: str = "common", max_workers: int = 20) -> dict[str, object]:
    """
    [요구사항 구현] 대역 병렬 스캔
    반환 형식: {"hosts": [{"ip":..., "status":..., "open_ports": [...]}]}
    """
    nm = nmap.PortScanner()
    # 1단계: Host Discovery (Ping 스캔으로 살아있는 IP만 추출)
    nm.scan(hosts=scope, arguments="-sn")
    live_hosts = nm.all_hosts()
    
    results = []
    # 2단계: ThreadPoolExecutor로 병렬 상세 스캔 실행
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(scan_single_host, ip, profile): ip for ip in live_hosts}
        
        for future in as_completed(future_to_ip):
            try:
                data = future.result()
                # 팀원 요청 형식에 맞춰 필드 필터링
                results.append({
                    "ip": data["ip"],
                    "status": data["status"],
                    "open_ports": data["open_ports"]
                })
            except Exception:
                pass

    return {"hosts": sorted(results, key=lambda x: x["ip"])}

def run_nmap_scan(target: str, profile: str = "common") -> dict[str, object]:
    """기존 단일 타겟 스캔 (기존 백엔드/대시보드 호환용)"""
    started_at = datetime.now(timezone.utc).astimezone()
    res = scan_single_host(target, profile)
    
    return {
        "scan_id": f"scan-{uuid4().hex[:8]}",
        "target": {"input_value": target, "resolved_ip": res["ip"]},
        "scan": {
            "started_at": started_at.isoformat(),
            "status": res["status"],
            "ports": res["ports"],
            "logs": []
        }
    }