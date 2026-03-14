"""FastAPI entrypoint for Tribest ASM."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import requests

from analysis.analyzer import AnalyzerConfig, analyze
from backend.app.config import settings
from backend.app.schemas import AnalyzeRequest, ReportResponse, ScanRequest, WorkflowResponse
from backend.app.services.report_service import build_report_bundle, build_report_payload
from backend.app.storage import Storage
from scanner.scan import run_scan

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Tribest ASM Backend", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

storage = Storage(settings.sqlite_path)
storage.initialize()
analyzer_config = AnalyzerConfig(
    use_live_nvd=settings.use_live_nvd,
    use_live_kev=settings.use_live_kev,
    use_live_epss=settings.use_live_epss,
    request_timeout=settings.request_timeout,
    nvd_api_key=settings.nvd_api_key,
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/scans")
def list_scans() -> dict[str, list[dict[str, Any]]]:
    return {"items": storage.list_scans()}


@app.get("/api/v1/ai/ollama/models")
def list_ollama_models(base_url: str = "http://host.docker.internal:11434") -> dict[str, Any]:
    try:
        response = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=5)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        return {"available": False, "models": [], "error": str(exc)}

    models = [
        item.get("name")
        for item in payload.get("models", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item.get("name").strip()
    ]
    return {"available": True, "models": models, "error": None}


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str) -> dict[str, Any]:
    scan = storage.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


@app.get("/api/v1/analyses/{scan_id}")
def get_analysis(scan_id: str) -> dict[str, Any]:
    analysis_result = storage.get_analysis(scan_id)
    if analysis_result is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return analysis_result


@app.post("/api/v1/scans/run")
def run_scan_endpoint(payload: ScanRequest) -> dict[str, Any]:
    scan_result = run_scan(payload.target, profile=payload.profile)
    storage.save_scan(scan_result)
    return scan_result


@app.post("/api/v1/analysis/run")
def run_analysis(payload: AnalyzeRequest) -> dict[str, Any]:
    scan_result = storage.get_scan(payload.scan_id)
    if scan_result is None:
        raise HTTPException(status_code=404, detail="scan not found")
    previous_scan = storage.get_previous_scan_for_target(scan_result["target"]["input_value"], payload.scan_id)
    analysis_result = analyze(scan_result, previous_scan=previous_scan, config=analyzer_config).to_dict()
    storage.save_analysis(analysis_result)
    return analysis_result


def _run_workflow(payload: ScanRequest) -> WorkflowResponse:
    scan_result = run_scan(payload.target, profile=payload.profile)
    storage.save_scan(scan_result)
    previous_scan = storage.get_previous_scan_for_target(scan_result["target"]["input_value"], scan_result["scan_id"])
    analysis_result = analyze(scan_result, previous_scan=previous_scan, config=analyzer_config).to_dict()
    storage.save_analysis(analysis_result)
    report_payload = build_report_payload(
        scan_result=scan_result,
        analysis_result=analysis_result,
        previous_scan=previous_scan,
        narrative_backend="template",
    )
    storage.save_report(report_payload)
    return WorkflowResponse(scan_result=scan_result, analysis_result=analysis_result)


@app.post("/api/v1/workflows/run", response_model=WorkflowResponse)
def run_workflow(payload: ScanRequest) -> WorkflowResponse:
    return _run_workflow(payload)


@app.post("/api/v1/workflows/demo", response_model=WorkflowResponse, deprecated=True)
def run_demo_workflow(payload: ScanRequest) -> WorkflowResponse:
    return _run_workflow(payload)


def _generate_report_payload(
    scan_id: str,
    *,
    narrative_backend: str = "template",
    gemini_api_key: str | None = None,
    gemini_model: str | None = None,
    ollama_base_url: str | None = None,
    ollama_model: str | None = None,
) -> dict[str, Any]:
    scan_result = storage.get_scan(scan_id)
    analysis_result = storage.get_analysis(scan_id)
    if scan_result is None or analysis_result is None:
        raise HTTPException(status_code=404, detail="scan or analysis not found")

    previous_scan = storage.get_previous_scan_for_target(scan_result["target"]["input_value"], scan_id)
    report_payload = build_report_payload(
        scan_result=scan_result,
        analysis_result=analysis_result,
        previous_scan=previous_scan,
        narrative_backend=narrative_backend,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
        ollama_base_url=ollama_base_url,
        ollama_model=ollama_model,
    )
    storage.save_report(report_payload)
    return report_payload


@app.get("/api/v1/reports/{scan_id}")
def get_report(scan_id: str) -> dict[str, Any]:
    report_payload = storage.get_report(scan_id)
    if report_payload is not None:
        return report_payload
    return _generate_report_payload(scan_id, narrative_backend="template")


@app.post("/api/v1/reports/{scan_id}/regenerate")
def regenerate_report(
    scan_id: str,
    narrative_backend: str = "template",
    gemini_api_key: str | None = None,
    gemini_model: str | None = None,
    ollama_base_url: str | None = None,
    ollama_model: str | None = None,
) -> dict[str, Any]:
    return _generate_report_payload(
        scan_id,
        narrative_backend=narrative_backend,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
        ollama_base_url=ollama_base_url,
        ollama_model=ollama_model,
    )


@app.post("/api/v1/reports/{scan_id}", response_model=ReportResponse)
def create_report(scan_id: str) -> ReportResponse:
    report_payload = get_report(scan_id)
    formats = build_report_bundle(scan_id, report_payload)
    return ReportResponse(scan_id=scan_id, formats=formats)
