"""
FastAPI routes for the AI AppSec Service.

Grouped by domain:
  /api/auth/*       – register, login, logout, me
  /api/scan-requests – create, list, get
  /api/scan-runs/*  – findings, trigger scan
  /api/findings/*   – status updates (mark fixed, verify, close)
  /api/certifications – issue, list
  /api/admin/*      – user management
  /api/ai-assist    – Perplexity-powered remediation
  /api/dashboard/*  – enterprise aggregate data
"""

import datetime
import threading
import logging
import os
import httpx
from pydantic import BaseModel
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session
from sqlalchemy import func

from src.models.database import (
    get_db, User, ScanRequest, ScanRun, Finding, Certification,
    Session as AuthSession,
)
from src.auth.middleware import (
    get_current_user, require_login, RequireRole, create_session, invalidate_session,
)
from src.core.orchestrator import run_scan

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")


# ══════════════════════════════════════════════════════════════════════════════
# Request / Response schemas
# ══════════════════════════════════════════════════════════════════════════════

class RegisterRequest(BaseModel):
    username: str
    email: str
    display_name: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

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

class FindingStatusUpdate(BaseModel):
    status: str  # fixed | verified | closed | open (reopen)
    notes: Optional[str] = None

class CertificationCreate(BaseModel):
    scan_request_id: int
    notes: Optional[str] = None
    valid_days: Optional[int] = 365

class AIAssistRequest(BaseModel):
    finding_id: int

class UserUpdate(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None
    display_name: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/auth/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user (default role: requester)."""
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(400, "Username already taken")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(400, "Email already registered")

    user = User(
        username=payload.username,
        email=payload.email,
        display_name=payload.display_name,
        role="requester",  # default role; admin can change later
    )
    user.set_password(payload.password)
    db.add(user)
    db.commit()
    db.refresh(user)

    return {"message": "Registration successful", "user_id": user.id, "role": user.role}


@router.post("/auth/login")
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    """Login and set session cookie."""
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not user.check_password(payload.password):
        raise HTTPException(401, "Invalid credentials")
    if not user.is_active:
        raise HTTPException(403, "Account is disabled")

    session = create_session(db, user)

    response.set_cookie(
        key="session_token",
        value=session.token,
        httponly=True,
        max_age=86400,  # 24 hours
        samesite="lax",
        path="/",
    )

    return {
        "message": "Login successful",
        "user": {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "email": user.email,
            "role": user.role,
        },
    }


@router.post("/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Logout – invalidate session."""
    token = request.cookies.get("session_token")
    if token:
        invalidate_session(db, token)
    response.delete_cookie("session_token", path="/")
    return {"message": "Logged out"}


@router.get("/auth/me")
def get_me(request: Request, db: Session = Depends(get_db)):
    """Get current authenticated user info."""
    user = get_current_user(request, db)
    if not user:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "user": {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "email": user.email,
            "role": user.role,
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# SCAN REQUEST ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/scan-requests", response_model=dict)
def create_scan_request(
    payload: ScanRequestCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    """Create a scan request. Authenticated requesters auto-link; anonymous still allowed for alpha."""
    user = get_current_user(request, db)

    scan_req = ScanRequest(
        requester_user_id=user.id if user else None,
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

    logger.info(f"Created ScanRequest {scan_req.id} by user={user.username if user else 'anonymous'}")
    return {"scan_request_id": scan_req.id, "status": "submitted"}


@router.get("/scan-requests/{scan_request_id}")
def get_scan_request(scan_request_id: int, db: Session = Depends(get_db)):
    """Get scan request details and latest scan run status."""
    scan_req = db.query(ScanRequest).filter(ScanRequest.id == scan_request_id).first()
    if not scan_req:
        raise HTTPException(status_code=404, detail="Scan request not found")

    latest_run = (
        db.query(ScanRun)
        .filter(ScanRun.scan_request_id == scan_request_id)
        .order_by(ScanRun.id.desc())
        .first()
    )

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
            "open": sum(1 for f in findings if f.status == "open"),
            "fixed": sum(1 for f in findings if f.status == "fixed"),
            "verified": sum(1 for f in findings if f.status == "verified"),
            "closed": sum(1 for f in findings if f.status == "closed"),
        }

    # Get certifications
    certs = db.query(Certification).filter(
        Certification.scan_request_id == scan_request_id
    ).order_by(Certification.id.desc()).all()

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
            "requester_user_id": scan_req.requester_user_id,
        },
        "latest_run": {
            "id": latest_run.id,
            "status": latest_run.status,
            "started_at": str(latest_run.started_at) if latest_run.started_at else None,
            "finished_at": str(latest_run.finished_at) if latest_run.finished_at else None,
            "engine_versions": latest_run.engine_versions,
        } if latest_run else None,
        "finding_summary": finding_summary,
        "certifications": [
            {
                "id": c.id,
                "issued_at": str(c.issued_at),
                "issued_by": c.issuer.display_name if c.issuer else "Unknown",
                "notes": c.notes,
                "valid_until": str(c.valid_until) if c.valid_until else None,
            }
            for c in certs
        ],
    }


@router.get("/scan-requests")
def list_scan_requests(request: Request, db: Session = Depends(get_db)):
    """List scan requests. Requesters see only their own; Scanner/Executive/Admin see all."""
    user = get_current_user(request, db)

    query = db.query(ScanRequest).order_by(ScanRequest.id.desc())

    # Requesters see only their own
    if user and user.role == "requester":
        query = query.filter(ScanRequest.requester_user_id == user.id)

    requests = query.limit(100).all()
    result = []
    for req in requests:
        latest_run = (
            db.query(ScanRun)
            .filter(ScanRun.scan_request_id == req.id)
            .order_by(ScanRun.id.desc())
            .first()
        )

        # Count finding statuses
        finding_counts = {}
        if latest_run:
            findings = db.query(Finding).filter(Finding.scan_run_id == latest_run.id).all()
            finding_counts = {
                "total": len(findings),
                "open": sum(1 for f in findings if f.status == "open"),
                "closed": sum(1 for f in findings if f.status == "closed"),
            }

        # Check certification
        cert = db.query(Certification).filter(
            Certification.scan_request_id == req.id
        ).order_by(Certification.id.desc()).first()

        result.append({
            "id": req.id,
            "created_at": str(req.created_at),
            "app_name": req.app_name,
            "team": req.team,
            "branch": req.branch,
            "requester_name": req.requester_name,
            "status": latest_run.status if latest_run else "submitted",
            "run_id": latest_run.id if latest_run else None,
            "findings": finding_counts,
            "certified": cert is not None,
        })
    return {"scan_requests": result}


# ══════════════════════════════════════════════════════════════════════════════
# SCAN RUN ROUTES (Scanner-initiated)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/scan-requests/{scan_request_id}/trigger")
def trigger_scan(
    scan_request_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    """Trigger a scan for a request. Scanner/Admin only."""
    user = get_current_user(request, db)
    if not user or user.role not in ("scanner", "admin"):
        raise HTTPException(403, "Only scanners can trigger scans")

    scan_req = db.query(ScanRequest).filter(ScanRequest.id == scan_request_id).first()
    if not scan_req:
        raise HTTPException(404, "Scan request not found")

    # Check if already running
    active_run = (
        db.query(ScanRun)
        .filter(
            ScanRun.scan_request_id == scan_request_id,
            ScanRun.status.in_(["pending", "running"]),
        )
        .first()
    )
    if active_run:
        raise HTTPException(400, "A scan is already in progress for this request")

    thread = threading.Thread(target=run_scan, args=(scan_request_id, user.id if user else None), daemon=True)
    thread.start()

    return {"message": "Scan triggered", "scan_request_id": scan_request_id}


@router.get("/scan-runs/{scan_run_id}/findings")
def get_findings(scan_run_id: int, db: Session = Depends(get_db)):
    """Get all findings for a scan run."""
    scan_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan run not found")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_run_id == scan_run_id)
        .order_by(Finding.severity.asc(), Finding.category.desc())
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
                "short_title": f.short_title,
                "description": f.description,
                "impact": f.impact,
                "location": f.location,
                "evidence_snippet": f.evidence_snippet,
                "status": f.status,
                "fix_notes": f.fix_notes,
                "verification_notes": f.verification_notes,
                "status_updated_at": str(f.status_updated_at) if f.status_updated_at else None,
            }
            for f in findings
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# FINDING STATUS ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@router.patch("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Update finding status. Role-based rules:
      - Requester can: open → fixed
      - Scanner can: fixed → verified, verified → closed, any → open (reopen)
    """
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(401, "Authentication required")

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    new_status = payload.status.lower()
    valid_statuses = {"open", "fixed", "verified", "closed"}
    if new_status not in valid_statuses:
        raise HTTPException(400, f"Invalid status. Must be one of: {valid_statuses}")

    current = finding.status

    # Requester rules
    if user.role == "requester":
        if new_status == "fixed" and current == "open":
            finding.fix_notes = payload.notes
        else:
            raise HTTPException(403, "Requesters can only mark open findings as fixed")

    # Scanner rules
    elif user.role in ("scanner", "admin"):
        if new_status == "verified" and current == "fixed":
            finding.verification_notes = payload.notes
        elif new_status == "closed" and current == "verified":
            finding.verification_notes = payload.notes
        elif new_status == "open":
            # Reopen
            finding.fix_notes = None
            finding.verification_notes = None
        else:
            raise HTTPException(400, f"Invalid transition: {current} → {new_status}")
    else:
        raise HTTPException(403, "Insufficient permissions")

    finding.status = new_status
    finding.status_updated_at = datetime.datetime.utcnow()
    finding.status_updated_by = user.id
    db.commit()

    return {"message": f"Finding #{finding_id} updated to {new_status}", "status": new_status}


# ══════════════════════════════════════════════════════════════════════════════
# CERTIFICATION ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/certifications")
def issue_certification(
    payload: CertificationCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    """Issue a certification for a scan request. Scanner/Admin only."""
    user = get_current_user(request, db)
    if not user or user.role not in ("scanner", "admin"):
        raise HTTPException(403, "Only scanners can issue certifications")

    scan_req = db.query(ScanRequest).filter(ScanRequest.id == payload.scan_request_id).first()
    if not scan_req:
        raise HTTPException(404, "Scan request not found")

    # Check all findings are closed
    latest_run = (
        db.query(ScanRun)
        .filter(ScanRun.scan_request_id == payload.scan_request_id)
        .order_by(ScanRun.id.desc())
        .first()
    )
    if latest_run:
        open_findings = (
            db.query(Finding)
            .filter(Finding.scan_run_id == latest_run.id, Finding.status != "closed")
            .count()
        )
        if open_findings > 0:
            raise HTTPException(400, f"{open_findings} findings are not yet closed. All must be closed before certification.")

    valid_until = None
    if payload.valid_days:
        valid_until = datetime.datetime.utcnow() + datetime.timedelta(days=payload.valid_days)

    cert = Certification(
        scan_request_id=payload.scan_request_id,
        issued_by=user.id,
        notes=payload.notes,
        valid_until=valid_until,
    )
    db.add(cert)
    db.commit()
    db.refresh(cert)

    return {
        "message": "Certification issued",
        "certification_id": cert.id,
        "valid_until": str(valid_until) if valid_until else None,
    }


@router.get("/certifications")
def list_certifications(db: Session = Depends(get_db)):
    """List all certifications."""
    certs = db.query(Certification).order_by(Certification.id.desc()).limit(100).all()
    return {
        "certifications": [
            {
                "id": c.id,
                "scan_request_id": c.scan_request_id,
                "app_name": c.scan_request.app_name if c.scan_request else "Unknown",
                "team": c.scan_request.team if c.scan_request else "Unknown",
                "issued_at": str(c.issued_at),
                "issued_by": c.issuer.display_name if c.issuer else "Unknown",
                "notes": c.notes,
                "valid_until": str(c.valid_until) if c.valid_until else None,
            }
            for c in certs
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/admin/users")
def list_users(
    request: Request,
    db: Session = Depends(get_db),
):
    """List all users. Admin only."""
    user = get_current_user(request, db)
    if not user or user.role != "admin":
        raise HTTPException(403, "Admin access required")

    users = db.query(User).order_by(User.id).all()
    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "display_name": u.display_name,
                "role": u.role,
                "is_active": u.is_active,
                "created_at": str(u.created_at),
                "last_login": str(u.last_login) if u.last_login else None,
            }
            for u in users
        ],
    }


@router.patch("/admin/users/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    """Update a user's role or active status. Admin only."""
    admin = get_current_user(request, db)
    if not admin or admin.role != "admin":
        raise HTTPException(403, "Admin access required")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")

    if payload.role is not None:
        valid_roles = {"requester", "scanner", "executive", "admin"}
        if payload.role not in valid_roles:
            raise HTTPException(400, f"Invalid role. Must be one of: {valid_roles}")
        user.role = payload.role

    if payload.is_active is not None:
        user.is_active = payload.is_active

    if payload.display_name is not None:
        user.display_name = payload.display_name

    db.commit()
    return {"message": f"User {user.username} updated", "role": user.role, "is_active": user.is_active}


# ══════════════════════════════════════════════════════════════════════════════
# AI ASSISTANT ROUTES (Perplexity integration)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/ai-assist")
async def ai_assist(
    payload: AIAssistRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Get AI-powered remediation guidance for a finding.
    Uses Perplexity API as the backend LLM.
    """
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(401, "Authentication required")

    finding = db.query(Finding).filter(Finding.id == payload.finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    # Get scan context
    scan_run = finding.scan_run
    scan_req = scan_run.scan_request if scan_run else None

    # Build prompt
    context = f"""You are a senior application security engineer helping a development team fix a security vulnerability.

Finding Details:
- Title: {finding.short_title}
- Severity: {finding.severity}
- Category: {finding.category}
- Risk Type: {finding.risk_type}
- OWASP LLM ID: {finding.owasp_llm_id or 'N/A'}
- Control ID: {finding.control_id or 'N/A'}
- Description: {finding.description or 'N/A'}
- Impact: {finding.impact or 'N/A'}
- Location: {finding.location or 'N/A'}
- Evidence: {finding.evidence_snippet or 'N/A'}

Application Context:
- App Name: {scan_req.app_name if scan_req else 'N/A'}
- LLM Usage: {scan_req.llm_usage if scan_req else 'N/A'}
- Data Profile: {scan_req.data_profile if scan_req else 'N/A'}

Provide:
1. A clear explanation of the vulnerability and why it matters
2. A specific code fix or remediation steps (with code examples)
3. Any compensating controls if a direct fix isn't immediately possible
4. Testing guidance to verify the fix works

Keep the response practical and actionable. Use code blocks for any code examples."""

    api_key = os.environ.get("PERPLEXITY_API_KEY", "")

    if not api_key:
        # Fallback: generate a structured response without API
        return {
            "finding_id": finding.id,
            "remediation": _generate_fallback_remediation(finding),
            "source": "built-in",
        }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.perplexity.ai/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "sonar",
                    "messages": [
                        {"role": "system", "content": "You are a senior application security engineer."},
                        {"role": "user", "content": context},
                    ],
                    "max_tokens": 2000,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]

            return {
                "finding_id": finding.id,
                "remediation": content,
                "source": "perplexity",
            }

    except Exception as e:
        logger.error(f"Perplexity API error: {e}")
        return {
            "finding_id": finding.id,
            "remediation": _generate_fallback_remediation(finding),
            "source": "built-in-fallback",
            "error": str(e),
        }


def _generate_fallback_remediation(finding: Finding) -> str:
    """Generate built-in remediation guidance without external API."""
    remediation_map = {
        "SQL injection": "**Fix:** Use parameterized queries or ORM methods. Never concatenate user input into SQL.\n\n```python\n# Bad\ncursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n# Good\ncursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n```",
        "Command injection": "**Fix:** Avoid `os.system()` and `subprocess.run(shell=True)`. Use `subprocess.run()` with a list of arguments.\n\n```python\n# Bad\nos.system(f\"ping {host}\")\n\n# Good\nsubprocess.run([\"ping\", host], capture_output=True)\n```",
        "Prompt injection": "**Fix:** Implement input sanitisation and output validation. Use a system prompt that defines boundaries. Consider a prompt firewall.\n\n1. Sanitise user inputs before passing to LLM\n2. Validate LLM outputs before executing any actions\n3. Use role-based prompting with clear boundaries\n4. Implement content filtering on responses",
        "Cross-site scripting": "**Fix:** Always escape user output. Use template engines with auto-escaping. Implement Content-Security-Policy headers.\n\n```python\n# Use Jinja2 auto-escaping (enabled by default)\n# Or explicitly: {{ user_input | e }}\n```",
        "SSRF": "**Fix:** Validate and allowlist URLs before making server-side requests. Block internal network ranges.\n\n```python\nfrom urllib.parse import urlparse\n\nALLOWED_HOSTS = ['api.example.com']\nparsed = urlparse(url)\nif parsed.hostname not in ALLOWED_HOSTS:\n    raise ValueError('URL not allowed')\n```",
        "Hardcoded secret": "**Fix:** Move secrets to environment variables or a secrets manager. Never commit secrets to source control.\n\n```python\nimport os\napi_key = os.environ['API_KEY']  # Not hardcoded\n```",
    }

    for key, guidance in remediation_map.items():
        if key.lower() in (finding.risk_type or "").lower():
            return guidance

    return f"""**General Remediation Guidance for: {finding.risk_type}**

1. Review the vulnerable code at: {finding.location or 'the reported location'}
2. Understand the attack vector described in the finding
3. Apply the principle of least privilege
4. Validate all inputs and sanitise all outputs
5. Follow OWASP guidelines for {finding.category} vulnerabilities
6. Test the fix with both positive and negative test cases

Refer to OWASP guidelines for detailed remediation: https://owasp.org/www-project-top-ten/"""


# ══════════════════════════════════════════════════════════════════════════════
# ENTERPRISE DASHBOARD ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/dashboard/aggregate")
def dashboard_aggregate(request: Request, db: Session = Depends(get_db)):
    """Aggregate security posture data for the enterprise dashboard."""
    # Total scans
    total_requests = db.query(ScanRequest).count()
    total_runs = db.query(ScanRun).filter(ScanRun.status == "completed").count()

    # Finding severity distribution (across all completed scans)
    all_findings = (
        db.query(Finding)
        .join(ScanRun, Finding.scan_run_id == ScanRun.id)
        .filter(ScanRun.status == "completed")
        .all()
    )

    severity_counts = {"P1": 0, "P2": 0, "P3": 0}
    status_counts = {"open": 0, "fixed": 0, "verified": 0, "closed": 0}
    category_counts = {"Traditional": 0, "AI/LLM": 0}

    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        status_counts[f.status] = status_counts.get(f.status, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    total_findings = len(all_findings)
    closure_rate = round((status_counts["closed"] / total_findings * 100), 1) if total_findings > 0 else 0

    # Certifications
    total_certs = db.query(Certification).count()
    active_certs = db.query(Certification).filter(
        Certification.valid_until > datetime.datetime.utcnow()
    ).count()

    # Top risk types
    risk_type_counts = {}
    for f in all_findings:
        if f.status != "closed":
            risk_type_counts[f.risk_type] = risk_type_counts.get(f.risk_type, 0) + 1
    top_risks = sorted(risk_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "overview": {
            "total_applications": total_requests,
            "total_scans_completed": total_runs,
            "total_findings": total_findings,
            "closure_rate": closure_rate,
            "total_certifications": total_certs,
            "active_certifications": active_certs,
        },
        "severity_distribution": severity_counts,
        "status_distribution": status_counts,
        "category_distribution": category_counts,
        "top_open_risks": [{"risk_type": r, "count": c} for r, c in top_risks],
    }


@router.get("/dashboard/apps")
def dashboard_per_app(request: Request, db: Session = Depends(get_db)):
    """Per-application security breakdown for enterprise dashboard."""
    requests = db.query(ScanRequest).order_by(ScanRequest.id.desc()).limit(50).all()

    apps = []
    for req in requests:
        latest_run = (
            db.query(ScanRun)
            .filter(ScanRun.scan_request_id == req.id, ScanRun.status == "completed")
            .order_by(ScanRun.id.desc())
            .first()
        )

        if not latest_run:
            apps.append({
                "id": req.id,
                "app_name": req.app_name,
                "team": req.team,
                "scan_status": "pending",
                "findings": {},
                "certified": False,
            })
            continue

        findings = db.query(Finding).filter(Finding.scan_run_id == latest_run.id).all()

        cert = db.query(Certification).filter(
            Certification.scan_request_id == req.id
        ).order_by(Certification.id.desc()).first()

        apps.append({
            "id": req.id,
            "app_name": req.app_name,
            "team": req.team,
            "branch": req.branch,
            "scan_status": latest_run.status,
            "scanned_at": str(latest_run.finished_at) if latest_run.finished_at else None,
            "findings": {
                "total": len(findings),
                "p1": sum(1 for f in findings if f.severity == "P1"),
                "p2": sum(1 for f in findings if f.severity == "P2"),
                "p3": sum(1 for f in findings if f.severity == "P3"),
                "open": sum(1 for f in findings if f.status == "open"),
                "closed": sum(1 for f in findings if f.status == "closed"),
            },
            "certified": cert is not None,
            "cert_valid_until": str(cert.valid_until) if cert and cert.valid_until else None,
        })

    return {"apps": apps}
