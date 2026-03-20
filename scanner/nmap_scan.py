from __future__ import annotations

import json
import re
import socket
from datetime import datetime, timezone
from uuid import uuid4

import nmap

TARGET_IPS = {
    "juice-shop": "172.28.0.11",
    "juice-shop.lab.local": "172.28.0.11",
    "tomcat-cve-2017-12615": "172.28.0.10",
    "tomcat-cve-2017-12615.lab.local": "172.28.0.10",
    "redis-4-unacc": "172.28.0.20",
    "redis-4-unacc.lab.local": "172.28.0.20",
    "sambacry": "172.28.0.30",
    "sambacry.lab.local": "172.28.0.30",
    "mysql-cve-2012-2122": "172.28.0.60",
    "mysql-cve-2012-2122.lab.local": "172.28.0.60",
    "elasticsearch-cve-2015-1427": "172.28.0.70",
    "elasticsearch-cve-2015-1427.lab.local": "172.28.0.70",
    "vsftpd-2-3-4": "172.28.0.80",
    "vsftpd-2-3-4.lab.local": "172.28.0.80",
}

PROFILE_CONFIG = {
    "quick": {
        "ports": "21,22,80,139,443,445,3000,8080,3306,6379,9200",
        "args": "-sV",
    },
    "common": {
        "ports": None,
        "args": "-sV --top-ports 100",
    },
    "deep": {
        "ports": None,
        "args": "-sV --top-ports 1000",
    },
    "full": {
        "ports": None,
        "args": "-sV -p-",
    },
    "web": {
        "ports": "80,443,3000,8080,8443",
        "args": "-sV",
    },
}


def is_ip(address: str) -> bool:
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(ip_pattern.match(address))


def run_nmap_scan(target_input: str, profile: str = "common") -> dict[str, object]:
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

    profile_config = PROFILE_CONFIG.get(profile, PROFILE_CONFIG["common"])

    nm = nmap.PortScanner()
    started_at = datetime.now(timezone.utc).astimezone().isoformat()
    scan_args = profile_config["args"]
    scan_target_ports = profile_config["ports"]
    nm.scan(target_ip, scan_target_ports, scan_args)
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

    if scan_target_ports:
        logged_command = f"nmap {scan_args} -p {scan_target_ports} {target_ip}"
    else:
        logged_command = f"nmap {scan_args} {target_ip}"

    try:
        csv_output = nm.csv()
    except Exception:
        csv_output = ""

    try:
        raw_output = json.dumps(nm._scan_result, ensure_ascii=False, indent=2, default=str)
    except Exception:
        raw_output = ""

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
                    "phase": "service_detection_csv",
                    "command": logged_command,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "return_code": 0,
                    "stdout": csv_output or f"Nmap scan completed for {target_ip}",
                    "stderr": "",
                },
                {
                    "source": "nmap",
                    "phase": "service_detection_raw",
                    "command": logged_command,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "return_code": 0,
                    "stdout": raw_output,
                    "stderr": "",
                }
            ],
        },
    }
