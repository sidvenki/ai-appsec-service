"""
AI AppSec Service – Main Application Entry Point

Internal security scanning service for Mastek's cyber team.
Runs traditional SAST/DAST + AI-specific SAST/DAST for agentic AI applications.
"""

import logging
import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from src.models.database import init_db, SessionLocal, ScanRequest, ScanRun, Finding
from src.api.routes import router as api_router

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── App setup ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="AI AppSec Service",
    description="Internal SAST/DAST scanning service for traditional and AI/LLM applications",
    version="0.1.0-alpha",
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


# ── HTML Pages ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Redirect to the scan request form."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/new-scan", response_class=HTMLResponse)
def new_scan_page(request: Request):
    """New Scan Request form page."""
    return templates.TemplateResponse("new_scan.html", {"request": request})


@app.get("/results/{scan_request_id}", response_class=HTMLResponse)
def results_page(request: Request, scan_request_id: int):
    """Scan Results page."""
    return templates.TemplateResponse("results.html", {
        "request": request,
        "scan_request_id": scan_request_id,
    })


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request):
    """Dashboard listing all scan requests."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
