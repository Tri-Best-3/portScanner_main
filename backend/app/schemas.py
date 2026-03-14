"""Pydantic schemas for the FastAPI layer."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1)
    profile: Literal["quick", "common", "deep", "full", "web"] = "common"


class AnalyzeRequest(BaseModel):
    scan_id: str = Field(..., min_length=1)


class WorkflowResponse(BaseModel):
    scan_result: dict
    analysis_result: dict


class ReportResponse(BaseModel):
    scan_id: str
    formats: dict[str, str]
