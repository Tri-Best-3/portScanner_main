"""Tests for the vulnerability analyzer."""

from __future__ import annotations

import requests

from analysis.analyzer import AnalyzerConfig, analyze
from analysis.cve_lookup import NvdLookupConfig, lookup_cves


SAMPLE_SCAN = {
    "scan_id": "scan-001",
    "target": {"input_value": "redis.lab.local", "resolved_ip": "192.168.56.20"},
    "scan": {
        "started_at": "2026-03-10T21:00:00+09:00",
        "ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "service": {"name": "ssh", "product": "OpenSSH", "version": "8.9p1"},
            },
            {
                "port": 6379,
                "protocol": "tcp",
                "service": {"name": "redis", "product": "Redis", "version": "4.0.14"},
            },
        ],
    },
}


def test_analyze_returns_expected_misconfiguration_findings() -> None:
    result = analyze(SAMPLE_SCAN).to_dict()

    assert result["scan_id"] == "scan-001"
    assert result["analysis"]["risk_summary"] == {"score": 82, "grade": "high"}
    titles = {item["title"] for item in result["analysis"]["vulnerabilities"]}
    assert "Redis Unauthorized Access" in titles
    assert "SSH Service Exposure" in titles
    assert result["drift"] == {"new_ports": [], "closed_ports": []}


def test_analyze_supports_planned_service_rules() -> None:
    scan = {
        "scan_id": "scan-003",
        "target": {"input_value": "infra.lab.local", "resolved_ip": "172.28.0.60"},
        "scan": {
            "started_at": "2026-03-10T21:10:00+09:00",
            "ports": [
                {
                    "port": 21,
                    "protocol": "tcp",
                    "service": {"name": "ftp", "product": "vsftpd", "version": "3.0.5"},
                },
                {
                    "port": 445,
                    "protocol": "tcp",
                    "service": {"name": "microsoft-ds", "product": "Samba", "version": "4.15.0"},
                },
                {
                    "port": 3306,
                    "protocol": "tcp",
                    "service": {"name": "mysql", "product": "MariaDB", "version": "10.5.23"},
                },
                {
                    "port": 9200,
                    "protocol": "tcp",
                    "service": {"name": "elasticsearch", "product": "Elasticsearch", "version": "7.17.0"},
                },
            ],
        },
    }

    result = analyze(scan).to_dict()
    titles = {item["title"] for item in result["analysis"]["vulnerabilities"]}

    assert "FTP Plaintext Service Exposure" in titles
    assert "Samba Service Exposure" in titles
    assert "Database Service Exposure" in titles
    assert "Elasticsearch Unauthorized Access Risk" in titles
    assert result["analysis"]["risk_summary"]["grade"] == "critical"


def test_analyze_computes_drift_when_previous_scan_is_given() -> None:
    previous_scan = {
        **SAMPLE_SCAN,
        "scan_id": "scan-000",
        "scan": {
            "started_at": "2026-03-09T21:00:00+09:00",
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": {"name": "ssh", "product": "OpenSSH", "version": "8.9p1"},
                },
                {
                    "port": 80,
                    "protocol": "tcp",
                    "service": {"name": "http", "product": "nginx", "version": "1.18.0"},
                },
            ],
        },
    }

    result = analyze(SAMPLE_SCAN, previous_scan=previous_scan).to_dict()

    assert result["drift"]["new_ports"] == [6379]
    assert result["drift"]["closed_ports"] == [80]


def test_live_cve_lookup_falls_back_to_offline_catalog() -> None:
    class BrokenSession(requests.Session):
        def get(self, *args, **kwargs):  # type: ignore[override]
            raise requests.RequestException("network blocked")

    findings = lookup_cves(
        service={"name": "http", "product": "nginx", "version": "1.18.0"},
        config=NvdLookupConfig(use_live_api=True),
        session=BrokenSession(),
    )
    assert any(item.cve_id == "CVE-2021-23017" for item in findings)

    result = analyze(
        {
            "scan_id": "scan-002",
            "target": {"input_value": "web.lab.local", "resolved_ip": "192.168.56.30"},
            "scan": {
                "started_at": "2026-03-10T22:00:00+09:00",
                "ports": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "service": {"name": "http", "product": "nginx", "version": "1.18.0"},
                    }
                ],
            },
        },
        config=AnalyzerConfig(use_live_nvd=True, use_live_kev=True, use_live_epss=True),
    ).to_dict()

    assert result["analysis"]["risk_summary"]["score"] >= 35
    assert result["analysis"]["vulnerabilities"][0]["cve_id"] == "CVE-2021-23017"
