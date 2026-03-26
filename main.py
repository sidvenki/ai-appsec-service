"""
AI AppSec Service – Main Application Entry Point

Internal security scanning service for Mastek's cyber team.
Runs traditional SAST/DAST + AI-specific SAST/DAST for agentic AI applications.

Roles: Requester | Scanner | Executive | Admin
"""

import logging
import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse

from src.models.database import init_db, SessionLocal, ScanRequest, ScanRun, Finding
from src.api.routes import router as api_router
from src.auth.middleware import get_current_user

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── App setup ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="Mastek AI App Scan",
    description="Internal SAST/DAST scanning service for traditional and AI/LLM applications",
    version="0.4.0-alpha",
)

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Include API routes
app.include_router(api_router)

# Initialize database on startup
@app.on_event("startup")
def startup():
    init_db()
    logger.info("AI AppSec Service started – database initialized")


# ── Helper: inject user into template context ──────────────────────────────

def _get_user(request: Request):
    """Get current user for template rendering."""
    db = SessionLocal()
    try:
        user = get_current_user(request, db)
        if user:
            return {
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "role": user.role,
            }
        return None
    finally:
        db.close()


def _render(request: Request, template: str, extra_context: dict = None):
    """Render template with user context."""
    ctx = {"request": request, "user": _get_user(request)}
    if extra_context:
        ctx.update(extra_context)
    return templates.TemplateResponse(template, ctx)


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC PAGES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Landing page – redirects to role-appropriate page if logged in."""
    user = _get_user(request)
    if user:
        role = user["role"]
        if role == "requester":
            return RedirectResponse("/requester", status_code=302)
        elif role == "scanner":
            return RedirectResponse("/scanner", status_code=302)
        elif role == "executive":
            return RedirectResponse("/executive", status_code=302)
        elif role == "admin":
            return RedirectResponse("/admin", status_code=302)
    return _render(request, "index.html")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Login page."""
    user = _get_user(request)
    if user:
        return RedirectResponse("/", status_code=302)
    return _render(request, "login.html")


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    """Registration page."""
    return _render(request, "register.html")


# ══════════════════════════════════════════════════════════════════════════════
# REQUESTER PAGES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/requester", response_class=HTMLResponse)
def requester_portal(request: Request):
    """Requester home – lists their scan requests."""
    return _render(request, "requester/portal.html")


@app.get("/new-scan", response_class=HTMLResponse)
def new_scan_page(request: Request):
    """New Scan Request form page."""
    return _render(request, "new_scan.html")


@app.get("/results/{scan_request_id}", response_class=HTMLResponse)
def results_page(request: Request, scan_request_id: int):
    """Scan Results page – role-aware."""
    return _render(request, "results.html", {"scan_request_id": scan_request_id})


# ══════════════════════════════════════════════════════════════════════════════
# SCANNER PAGES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/scanner", response_class=HTMLResponse)
def scanner_portal(request: Request):
    """Scanner home – request queue + scan controls."""
    return _render(request, "scanner/portal.html")


# ══════════════════════════════════════════════════════════════════════════════
# EXECUTIVE PAGES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/executive", response_class=HTMLResponse)
def executive_dashboard(request: Request):
    """Enterprise security dashboard."""
    return _render(request, "executive/dashboard.html")


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN PAGES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    """Admin – user/role management."""
    return _render(request, "admin/users.html")


# ══════════════════════════════════════════════════════════════════════════════
# LEGACY ROUTES (keep for backwards compatibility)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request):
    """Legacy dashboard – redirects to role-appropriate page."""
    user = _get_user(request)
    if user:
        if user["role"] == "executive":
            return RedirectResponse("/executive", status_code=302)
        elif user["role"] == "scanner":
            return RedirectResponse("/scanner", status_code=302)
        elif user["role"] == "requester":
            return RedirectResponse("/requester", status_code=302)
    return _render(request, "scanner/portal.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
