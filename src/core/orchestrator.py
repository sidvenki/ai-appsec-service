"""
Scan orchestrator – the central workflow engine.

run_scan(scan_request_id):
  1. Fetch ScanRequest from DB
  2. Create ScanRun with status = "running"
  3. Create temp workspace (/tmp/scan-<id>/)
  4. git clone repo + checkout branch
  5. Run: Semgrep, Bandit, ZAP, AI-SAST, AI-DAST
  6. Parse outputs into Findings
  7. Assign severities + control_ids
  8. Delete temp workspace
  9. Mark ScanRun as "completed"
"""

import datetime
import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from src.models.database import SessionLocal, ScanRequest, ScanRun, Finding
from src.engines.sast.semgrep_runner import run_semgrep
from src.engines.sast.bandit_runner import run_bandit
from src.engines.dast.zap_runner import run_zap
from src.engines.ai_sast.rules import run_ai_sast
from src.engines.ai_dast.probes import run_ai_dast

logger = logging.getLogger(__name__)


def _get_engine_versions() -> dict:
    """Collect version strings of installed tools."""
    versions = {}
    for tool, cmd in [
        ("semgrep", ["semgrep", "--version"]),
        ("bandit", ["bandit", "--version"]),
        ("python", ["python3", "--version"]),
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            versions[tool] = result.stdout.strip() or result.stderr.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            versions[tool] = "not installed"
    return versions


def _clone_repo(repo_url: str, branch: str, workspace: str) -> bool:
    """Clone a git repo and checkout the specified branch."""
    logger.info(f"Cloning {repo_url} branch={branch} into {workspace}")
    try:
        result = subprocess.run(
            [
                "git", "clone",
                "--depth", "1",
                "--branch", branch,
                "--single-branch",
                repo_url,
                workspace,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            # Try without --branch (some repos use tags or the branch may be default)
            logger.warning(f"Shallow clone failed, trying full clone: {result.stderr[:200]}")
            if os.path.exists(workspace):
                shutil.rmtree(workspace)
            result = subprocess.run(
                ["git", "clone", repo_url, workspace],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                logger.error(f"Git clone failed: {result.stderr[:500]}")
                return False
            # Checkout the branch
            subprocess.run(
                ["git", "checkout", branch],
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=30,
            )
        return True
    except subprocess.TimeoutExpired:
        logger.error("Git clone timed out after 120s")
        return False


def run_scan(scan_request_id: int, initiated_by: int = None):
    """
    Main scan workflow. Designed to be called asynchronously.
    initiated_by: user ID of the scanner who triggered the scan (optional).
    """
    db = SessionLocal()
    workspace = None

    try:
        # ── 1. Fetch ScanRequest ───────────────────────────────────────
        scan_request = db.query(ScanRequest).filter(ScanRequest.id == scan_request_id).first()
        if not scan_request:
            logger.error(f"ScanRequest {scan_request_id} not found")
            return

        # ── 2. Create ScanRun ──────────────────────────────────────────
        engine_versions = _get_engine_versions()
        scan_run = ScanRun(
            scan_request_id=scan_request_id,
            status="running",
            started_at=datetime.datetime.utcnow(),
            engine_versions=json.dumps(engine_versions),
            initiated_by=initiated_by,
        )
        db.add(scan_run)
        db.commit()
        db.refresh(scan_run)

        logger.info(f"ScanRun {scan_run.id} started for ScanRequest {scan_request_id}")

        # ── 3. Create temp workspace ───────────────────────────────────
        workspace = tempfile.mkdtemp(prefix=f"scan-{scan_request_id}-")
        logger.info(f"Temp workspace: {workspace}")

        # ── 4. Clone repo ──────────────────────────────────────────────
        clone_success = _clone_repo(
            scan_request.repo_url,
            scan_request.branch,
            os.path.join(workspace, "repo"),
        )
        repo_path = os.path.join(workspace, "repo")

        all_findings_data = []

        if clone_success:
            # ── 5a. Traditional SAST ───────────────────────────────────
            logger.info("Running traditional SAST (Semgrep + Bandit)...")
            try:
                semgrep_findings = run_semgrep(repo_path)
                all_findings_data.extend(semgrep_findings)
            except Exception as e:
                logger.error(f"Semgrep failed: {e}")

            try:
                bandit_findings = run_bandit(repo_path)
                all_findings_data.extend(bandit_findings)
            except Exception as e:
                logger.error(f"Bandit failed: {e}")

            # ── 5c. AI-SAST ───────────────────────────────────────────
            logger.info("Running AI-SAST rule checks...")
            try:
                ai_sast_findings = run_ai_sast(repo_path)
                all_findings_data.extend(ai_sast_findings)
            except Exception as e:
                logger.error(f"AI-SAST failed: {e}")
        else:
            logger.warning("Repo clone failed – skipping all SAST checks")

        # ── 5b. Traditional DAST (ZAP) ─────────────────────────────────
        if scan_request.env_base_url:
            logger.info("Running traditional DAST (OWASP ZAP)...")
            try:
                zap_findings = run_zap(scan_request.env_base_url)
                all_findings_data.extend(zap_findings)
            except Exception as e:
                logger.error(f"ZAP failed: {e}")

            # ── 5d. AI-DAST probes ─────────────────────────────────────
            logger.info("Running AI-DAST probes...")
            try:
                ai_dast_findings = run_ai_dast(scan_request.env_base_url)
                all_findings_data.extend(ai_dast_findings)
            except Exception as e:
                logger.error(f"AI-DAST failed: {e}")
        else:
            logger.info("No env_base_url – skipping DAST")

        # ── 6. Persist findings ────────────────────────────────────────
        logger.info(f"Persisting {len(all_findings_data)} findings...")
        for fd in all_findings_data:
            finding = Finding(
                scan_run_id=scan_run.id,
                severity=fd.get("severity", "P3"),
                category=fd.get("category", "Traditional"),
                risk_type=fd.get("risk_type", "Unknown"),
                owasp_llm_id=fd.get("owasp_llm_id"),
                control_id=fd.get("control_id"),
                short_title=fd.get("short_title", "Untitled finding"),
                description=fd.get("description", ""),
                impact=fd.get("impact", ""),
                location=fd.get("location", ""),
                evidence_snippet=fd.get("evidence_snippet", "")[:2000],
            )
            db.add(finding)

        # ── 7. Mark completed ──────────────────────────────────────────
        scan_run.status = "completed"
        scan_run.finished_at = datetime.datetime.utcnow()
        db.commit()

        logger.info(
            f"ScanRun {scan_run.id} completed: {len(all_findings_data)} findings "
            f"({sum(1 for f in all_findings_data if f.get('severity') == 'P1')} P1, "
            f"{sum(1 for f in all_findings_data if f.get('severity') == 'P2')} P2, "
            f"{sum(1 for f in all_findings_data if f.get('severity') == 'P3')} P3)"
        )

    except Exception as e:
        logger.exception(f"Scan orchestrator error: {e}")
        # Try to mark the run as failed
        try:
            if 'scan_run' in dir() and scan_run:
                scan_run.status = "failed"
                scan_run.finished_at = datetime.datetime.utcnow()
                db.commit()
        except Exception:
            pass
    finally:
        # ── 8. Cleanup workspace ───────────────────────────────────────
        if workspace and os.path.exists(workspace):
            try:
                shutil.rmtree(workspace)
                logger.info(f"Cleaned up workspace: {workspace}")
            except Exception as e:
                logger.warning(f"Failed to clean up workspace: {e}")
        db.close()
