"""Pydantic schemas for backend contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


ProfileName = Literal["quick", "common", "deep", "full", "web"]
VerificationMethod = Literal["manual-curl", "nuclei-template", "custom"]
VerificationStatus = Literal["confirmed", "rejected", "needs_review"]


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1)
    profile: ProfileName = "common"
    scenario: str | None = None


class BatchScanRequest(BaseModel):
    targets: list[str] = Field(..., min_length=1)
    profile: ProfileName = "common"
    scenario: str | None = None
    max_concurrency: int = Field(default=4, ge=1, le=16)


class AnalyzeRequest(BaseModel):
    scan_id: str = Field(..., min_length=1)


class WorkflowResponse(BaseModel):
    scan_result: dict
    analysis_result: dict


class WorkflowBatchItem(BaseModel):
    target: str
    status: Literal["completed", "failed"]
    scan_id: str | None = None
    error: str | None = None


class WorkflowBatchResponse(BaseModel):
    run_id: str
    status: Literal["completed", "partial_failed", "failed"]
    items: list[WorkflowBatchItem]


class ReportResponse(BaseModel):
    scan_id: str
    formats: dict[str, str]


class InventoryRunRequest(BaseModel):
    scope: str = Field(..., min_length=1)
    profile: ProfileName = "quick"


class InventoryHost(BaseModel):
    ip: str
    status: Literal["up", "down"] = "up"
    open_ports: list[int] = Field(default_factory=list)


class InventoryHostChange(BaseModel):
    ip: str
    new_ports: list[int] = Field(default_factory=list)
    closed_ports: list[int] = Field(default_factory=list)


class InventoryDrift(BaseModel):
    new_hosts: list[str] = Field(default_factory=list)
    missing_hosts: list[str] = Field(default_factory=list)
    changed_hosts: list[InventoryHostChange] = Field(default_factory=list)


class InventoryRunResponse(BaseModel):
    inventory_id: str
    scope: str
    profile: ProfileName
    created_at: datetime
    hosts: list[InventoryHost]
    drift: InventoryDrift


class VerificationRecordRequest(BaseModel):
    scan_id: str = Field(..., min_length=1)
    template_id: str = Field(..., min_length=1)
    method: VerificationMethod = "manual-curl"
    status: VerificationStatus = "needs_review"
    target: str | None = None
    evidence: str = Field(..., min_length=1)
    raw_output: str | None = None


class VerificationRecordResponse(BaseModel):
    verification_id: str
    scan_id: str
    template_id: str
    method: VerificationMethod
    status: VerificationStatus
    target: str | None = None
    evidence: str
    raw_output: str | None = None
    created_at: datetime
