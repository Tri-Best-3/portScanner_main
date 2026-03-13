import nmap
import socket
import re
from datetime import datetime, timezone
from uuid import uuid4

def is_ip(address):
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(ip_pattern.match(address))

def run_nmap_scan(target_input: str, profile: str = "mixed"):
    # 1. 대상 식별 및 IP 변환
    if is_ip(target_input):
        target_ip = target_input
    else:
        try:
            target_ip = socket.gethostbyname(target_input)
        except socket.gaierror:
            return {"error": "도메인을 찾을 수 없습니다."}

    # 2. 프로젝트 기준 프로필로 변경 (quick, web, redis, mixed)
    port_map = {
        "quick": "80,443",
        "web": "80,443,8080",
        "redis": "6379,22",
        "mixed": "21,22,80,443,445,3306,6379,9200"
    }
    # 기본값은 mixed로 설정
    port_range = port_map.get(profile, port_map["mixed"])

    # 3. Nmap 실행
    nm = nmap.PortScanner()
    started_at = datetime.now(timezone.utc).astimezone().isoformat()
    
    nm.scan(target_ip, port_range, '-sV')
    finished_at = datetime.now(timezone.utc).astimezone().isoformat()

    # 4. 결과 파싱
    ports_data = []
    if target_ip in nm.all_hosts():
        for proto in nm[target_ip].all_protocols():
            for port in sorted(nm[target_ip][proto].keys()):
                port_info = nm[target_ip][proto][port]
                if port_info['state'] == 'open':
                    ports_data.append({
                        "port": int(port),
                        "protocol": proto,
                        "service": {
                            "name": port_info.get('name'),
                            "product": port_info.get('product'),
                            "version": port_info.get('version')
                        }
                    })

    # 5. 최종 리턴
    return {
        "scan_id": f"scan-{uuid4().hex[:8]}",
        "target": {
            "input_value": target_input,
            "resolved_ip": target_ip
        },
        "scan": {
            "started_at": started_at,
            "ports": ports_data,
            "logs": [
                {
                    "source": "nmap",
                    "phase": "service_detection",
                    "command": f"nmap -sV -p {port_range} {target_ip}",
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "return_code": 0,
                    "stdout": f"Nmap scan completed for {target_ip}",
                    "stderr": ""
                }
            ]
        }
    }