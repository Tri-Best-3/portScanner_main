"""FastAPI entrypoint for Tribest ASM."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from analysis.analyzer import analyze
from backend.app.config import settings
from backend.app.schemas import AnalyzeRequest, ReportResponse, ScanRequest, WorkflowResponse
from backend.app.services.report_service import build_report_bundle
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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/scans")
def list_scans() -> dict[str, list[dict[str, Any]]]:
    return {"items": storage.list_scans()}


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
    analysis_result = analyze(scan_result, previous_scan=previous_scan).to_dict()
    storage.save_analysis(analysis_result)
    return analysis_result


@app.post("/api/v1/workflows/demo", response_model=WorkflowResponse)
def run_demo_workflow(payload: ScanRequest) -> WorkflowResponse:
    scan_result = run_scan(payload.target, profile=payload.profile)
    storage.save_scan(scan_result)
    previous_scan = storage.get_previous_scan_for_target(scan_result["target"]["input_value"], scan_result["scan_id"])
    analysis_result = analyze(scan_result, previous_scan=previous_scan).to_dict()
    storage.save_analysis(analysis_result)
    return WorkflowResponse(scan_result=scan_result, analysis_result=analysis_result)


@app.post("/api/v1/reports/{scan_id}", response_model=ReportResponse)
def create_report(scan_id: str) -> ReportResponse:
    scan_result = storage.get_scan(scan_id)
    analysis_result = storage.get_analysis(scan_id)
    if scan_result is None or analysis_result is None:
        raise HTTPException(status_code=404, detail="scan or analysis not found")
    formats = build_report_bundle(scan_id, analysis_result)
    return ReportResponse(scan_id=scan_id, formats=formats)
