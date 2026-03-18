"""
FastAPI routes for the AI AppSec Service.

Endpoints:
  POST /api/scan-requests        – Create a new scan request + trigger async scan
  GET  /api/scan-requests/{id}   – Get scan request and latest run status
  GET  /api/scan-runs/{id}/findings – Get all findings for a run
"""

import threading
import logging
from pydantic import BaseModel, EmailStr
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.models.database import get_db, ScanRequest, ScanRun, Finding
from src.core.orchestrator import run_scan

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")


# ── Request / Response schemas ─────────────────────────────────────────────

class ScanRequestCreate(BaseModel):
    requester_name: str
    team: str
    email: str
    app_name: str
    description: Optional[str] = None
    repo_url: str
    branch: str
    env_base_url: Optional[str] = None
    llm_usage: Optional[str] = None
    data_profile: Optional[str] = None


class ScanRequestResponse(BaseModel):
    id: int
    created_at: str
    requester_name: str
    team: str
    email: str
    app_name: str
    description: Optional[str]
    repo_url: str
    branch: str
    env_base_url: Optional[str]
    llm_usage: Optional[str]
    data_profile: Optional[str]

    class Config:
        from_attributes = True


class ScanRunResponse(BaseModel):
    id: int
    scan_request_id: int
    started_at: Optional[str]
    finished_at: Optional[str]
    status: str
    engine_versions: Optional[str]

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: int
    scan_run_id: int
    severity: str
    category: str
    risk_type: str
    owasp_llm_id: Optional[str]
    control_id: Optional[str]
    source: str
    short_title: str
    description: Optional[str]
    impact: Optional[str]
    location: Optional[str]
    evidence_snippet: Optional[str]

    class Config:
        from_attributes = True


# ── Routes ─────────────────────────────────────────────────────────────────

@router.post("/scan-requests", response_model=dict)
def create_scan_request(payload: ScanRequestCreate, db: Session = Depends(get_db)):
    """Create a scan request and trigger an async scan."""
    scan_req = ScanRequest(
        requester_name=payload.requester_name,
        team=payload.team,
        email=payload.email,
        app_name=payload.app_name,
        description=payload.description,
        repo_url=payload.repo_url,
        branch=payload.branch,
        env_base_url=payload.env_base_url,
        llm_usage=payload.llm_usage,
        data_profile=payload.data_profile,
    )
    db.add(scan_req)
    db.commit()
    db.refresh(scan_req)

    # Trigger async scan in a background thread (alpha – no task queue yet)
    thread = threading.Thread(target=run_scan, args=(scan_req.id,), daemon=True)
    thread.start()

    logger.info(f"Created ScanRequest {scan_req.id}, scan triggered")
    return {"scan_request_id": scan_req.id, "status": "scan_triggered"}


@router.get("/scan-requests/{scan_request_id}")
def get_scan_request(scan_request_id: int, db: Session = Depends(get_db)):
    """Get scan request details and latest scan run status."""
    scan_req = db.query(ScanRequest).filter(ScanRequest.id == scan_request_id).first()
    if not scan_req:
        raise HTTPException(status_code=404, detail="Scan request not found")

    # Get latest scan run
    latest_run = (
        db.query(ScanRun)
        .filter(ScanRun.scan_request_id == scan_request_id)
        .order_by(ScanRun.id.desc())
        .first()
    )

    # Count findings by severity
    finding_summary = {}
    if latest_run:
        findings = db.query(Finding).filter(Finding.scan_run_id == latest_run.id).all()
        finding_summary = {
            "total": len(findings),
            "p1": sum(1 for f in findings if f.severity == "P1"),
            "p2": sum(1 for f in findings if f.severity == "P2"),
            "p3": sum(1 for f in findings if f.severity == "P3"),
            "traditional": sum(1 for f in findings if f.category == "Traditional"),
            "ai_llm": sum(1 for f in findings if f.category == "AI/LLM"),
        }

    return {
        "scan_request": {
            "id": scan_req.id,
            "created_at": str(scan_req.created_at),
            "requester_name": scan_req.requester_name,
            "team": scan_req.team,
            "email": scan_req.email,
            "app_name": scan_req.app_name,
            "description": scan_req.description,
            "repo_url": scan_req.repo_url,
            "branch": scan_req.branch,
            "env_base_url": scan_req.env_base_url,
            "llm_usage": scan_req.llm_usage,
            "data_profile": scan_req.data_profile,
        },
        "latest_run": {
            "id": latest_run.id,
            "status": latest_run.status,
            "started_at": str(latest_run.started_at) if latest_run.started_at else None,
            "finished_at": str(latest_run.finished_at) if latest_run.finished_at else None,
            "engine_versions": latest_run.engine_versions,
        } if latest_run else None,
        "finding_summary": finding_summary,
    }


@router.get("/scan-runs/{scan_run_id}/findings")
def get_findings(scan_run_id: int, db: Session = Depends(get_db)):
    """Get all findings for a scan run."""
    scan_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan run not found")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_run_id == scan_run_id)
        .order_by(
            # Sort P1 first, then P2, then P3
            Finding.severity.asc(),
            Finding.category.desc(),
        )
        .all()
    )

    return {
        "scan_run_id": scan_run_id,
        "status": scan_run.status,
        "total_findings": len(findings),
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "category": f.category,
                "risk_type": f.risk_type,
                "owasp_llm_id": f.owasp_llm_id,
                "control_id": f.control_id,
                "source": f.source,
                "short_title": f.short_title,
                "description": f.description,
                "impact": f.impact,
                "location": f.location,
                "evidence_snippet": f.evidence_snippet,
            }
            for f in findings
        ],
    }


@router.get("/scan-requests")
def list_scan_requests(db: Session = Depends(get_db)):
    """List all scan requests (most recent first)."""
    requests = db.query(ScanRequest).order_by(ScanRequest.id.desc()).limit(50).all()
    result = []
    for req in requests:
        latest_run = (
            db.query(ScanRun)
            .filter(ScanRun.scan_request_id == req.id)
            .order_by(ScanRun.id.desc())
            .first()
        )
        result.append({
            "id": req.id,
            "created_at": str(req.created_at),
            "app_name": req.app_name,
            "team": req.team,
            "branch": req.branch,
            "status": latest_run.status if latest_run else "pending",
            "run_id": latest_run.id if latest_run else None,
        })
    return {"scan_requests": result}
