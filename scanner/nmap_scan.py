from __future__ import annotations

import re
import socket
from datetime import datetime, timezone
from uuid import uuid4

import nmap

TARGET_IPS = {
    "web-target": "172.28.0.10",
    "web.lab.local": "172.28.0.10",
    "redis-vuln": "172.28.0.20",
    "redis.lab.local": "172.28.0.20",
    "samba-vuln": "172.28.0.30",
    "samba.lab.local": "172.28.0.30",
    "ssh-target": "172.28.0.40",
    "ssh.lab.local": "172.28.0.40",
    "other-service": "172.28.0.50",
}


def is_ip(address: str) -> bool:
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(ip_pattern.match(address))


def run_nmap_scan(target_input: str, profile: str = "mixed") -> dict[str, object]:
    normalized = target_input.strip().lower()
    if is_ip(normalized):
        target_ip = normalized
    elif normalized in TARGET_IPS:
        target_ip = TARGET_IPS[normalized]
    else:
        try:
            target_ip = socket.gethostbyname(target_input)
        except socket.gaierror as exc:
            raise ValueError("도메인을 찾을 수 없습니다.") from exc

    port_map = {
        "quick": "80,443",
        "web": "80,443,8080",
        "redis": "6379,22",
        "mixed": "21,22,80,443,445,3306,6379,9200",
    }
    port_range = port_map.get(profile, port_map["mixed"])

    nm = nmap.PortScanner()
    started_at = datetime.now(timezone.utc).astimezone().isoformat()
    nm.scan(target_ip, port_range, "-sV")
    finished_at = datetime.now(timezone.utc).astimezone().isoformat()

    ports_data: list[dict[str, object]] = []
    if target_ip in nm.all_hosts():
        for proto in nm[target_ip].all_protocols():
            for port in sorted(nm[target_ip][proto].keys()):
                port_info = nm[target_ip][proto][port]
                if port_info["state"] == "open":
                    ports_data.append(
                        {
                            "port": int(port),
                            "protocol": proto,
                            "service": {
                                "name": port_info.get("name"),
                                "product": port_info.get("product"),
                                "version": port_info.get("version"),
                            },
                        }
                    )

    return {
        "scan_id": f"scan-{uuid4().hex[:8]}",
        "target": {
            "input_value": target_input,
            "resolved_ip": target_ip,
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
                    "stderr": "",
                }
            ],
        },
    }
