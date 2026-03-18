"""
OWASP ZAP runner – invokes ZAP in headless/API scan mode and parses JSON output.

For alpha, we attempt to use zap-cli or the ZAP API.
If ZAP is not installed, we log a warning and return empty.
"""

import json
import subprocess
import logging
import os
from pathlib import Path
from src.core.severity import classify_traditional

logger = logging.getLogger(__name__)

# Map ZAP risk levels to our P-levels
ZAP_RISK_MAP = {
    "3": "P1",   # High
    "2": "P2",   # Medium
    "1": "P3",   # Low
    "0": "P3",   # Informational
}


def run_zap(target_url: str) -> list[dict]:
    """
    Run OWASP ZAP baseline scan against the target URL.
    Returns a list of normalised finding dicts.
    """
    if not target_url:
        logger.info("No env_base_url provided, skipping ZAP scan")
        return []

    findings = []
    report_path = f"/tmp/zap-report-{os.getpid()}.json"

    # Try zap-baseline.py (Docker-based) or zap-cli
    cmd = None
    for zap_cmd in [
        ["zap-baseline.py", "-t", target_url, "-J", report_path, "-I"],
        ["zap-cli", "quick-scan", "--self-contained", "--start-options", "-config api.disablekey=true", target_url],
    ]:
        try:
            subprocess.run([zap_cmd[0], "--version"], capture_output=True, timeout=10)
            cmd = zap_cmd
            break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    if cmd is None:
        logger.warning("OWASP ZAP not found. Skipping traditional DAST. Install ZAP for full coverage.")
        return []

    logger.info(f"Running ZAP: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )

        # Try to read the JSON report
        if os.path.exists(report_path):
            with open(report_path, "r") as f:
                report = json.load(f)
        else:
            # Try to parse stdout
            report = json.loads(result.stdout) if result.stdout.strip() else {}

        # ZAP JSON report structure
        for site in report.get("site", []):
            for alert in site.get("alerts", []):
                risk = str(alert.get("riskcode", "0"))
                name = alert.get("name", "Unknown alert")
                desc = alert.get("desc", "")
                solution = alert.get("solution", "")
                evidence = alert.get("evidence", "")[:500]
                uri = ""
                instances = alert.get("instances", [])
                if instances:
                    uri = instances[0].get("uri", "")

                classification = classify_traditional(name.lower().replace(" ", "_"))
                classification["severity"] = ZAP_RISK_MAP.get(risk, "P3")

                findings.append({
                    **classification,
                    "source": "Unknown",
                    "short_title": f"ZAP: {name}",
                    "description": desc[:1000],
                    "impact": solution[:500] if solution else f"DAST finding: {name}",
                    "location": uri or target_url,
                    "evidence_snippet": evidence,
                })

    except subprocess.TimeoutExpired:
        logger.error("ZAP timed out after 600s")
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"ZAP error: {e}")
    finally:
        if os.path.exists(report_path):
            os.remove(report_path)

    logger.info(f"ZAP produced {len(findings)} findings")
    return findings
