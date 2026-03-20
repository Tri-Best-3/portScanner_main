from __future__ import annotations

import json
import re
import socket
from datetime import datetime, timezone
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed

import nmap

# 기존 TARGET_IPS 및 PROFILE_CONFIG는 유지 (생략)
TARGET_IPS = { ... } 
PROFILE_CONFIG = { ... }

def is_ip_or_range(address: str) -> bool:
    """IP, CIDR(192.168.1.0/24), Range(10.0.0.1-10) 형식인지 확인"""
    # 간단한 정규식: 숫자, 점, 슬래시, 대시가 포함된 패턴
    range_pattern = re.compile(r"^[0-9./-]+$")
    return bool(range_pattern.match(address))

def scan_single_host(ip: str, profile: str = "common") -> dict[str, object]:
    """단일 호스트에 대한 포트 스캔 수행 (병렬 처리에 사용)"""
    config = PROFILE_CONFIG.get(profile, PROFILE_CONFIG["common"])
    nm = nmap.PortScanner()
    
    try:
        # -sn(Ping Scan) 대신 포트 스캔을 바로 수행하여 Open 포트 확인
        nm.scan(ip, config["ports"], config["args"])
        
        if ip not in nm.all_hosts():
            return {"ip": ip, "status": "down", "open_ports": []}

        open_ports = []
        for proto in nm[ip].all_protocols():
            for port in sorted(nm[ip][proto].keys()):
                if nm[ip][proto][port]["state"] == "open":
                    open_ports.append(int(port))
        
        return {
            "ip": ip,
            "status": "up",
            "open_ports": open_ports,
            "hostname": nm[ip].hostname(),
            "vendor": nm[ip].get("vendor", {})
        }
    except Exception:
        return {"ip": ip, "status": "error", "open_ports": []}

def run_inventory_scan(scope: str, profile: str = "common", max_workers: int = 10) -> dict[str, object]:
    """
    대역 스캔 및 병렬 포트 스캔 수행
    1. Host Discovery 우선 수행
    2. 발견된 Host들에 대해 병렬 포트 스캔
    """
    nm = nmap.PortScanner()
    # 1. Host Discovery (-sn: Ping Scan)
    print(f"[*] Discovering hosts in scope: {scope}...")
    nm.scan(hosts=scope, arguments="-sn")
    live_hosts = nm.all_hosts()

    results = []
    
    # 2. 병렬 포트 스캔 (ThreadPoolExecutor)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(scan_single_host, ip, profile): ip for ip in live_hosts}
        
        for future in as_completed(future_to_ip):
            try:
                data = future.result()
                results.append(data)
            except Exception as exc:
                ip = future_to_ip[future]
                print(f"[!] {ip} scan generated an exception: {exc}")

    return {
        "scan_id": f"inv-{uuid4().hex[:8]}",
        "scope": scope,
        "timestamp": datetime.now(timezone.utc).astimezone().isoformat(),
        "hosts": results
    }

def run_nmap_scan(target_input: str, profile: str = "common") -> dict[str, object]:
    """기존 단일 타겟 스캔 (호환성 유지용)"""
    # ... (기존 로직과 동일하되, 내부에서 scan_single_host를 호출하도록 리팩토링 가능)
    # 생략: 기존 반환 형식을 유지해야 하므로 그대로 두거나 내부 로직만 최적화