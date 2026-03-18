"""
Semgrep runner – invokes Semgrep CLI against a workspace and parses JSON output.
"""

import json
import subprocess
import logging
from pathlib import Path
from src.core.severity import classify_traditional

logger = logging.getLogger(__name__)


def run_semgrep(workspace_path: str) -> list[dict]:
    """
    Run Semgrep with auto-config on the given workspace.
    Returns a list of normalised finding dicts.
    """
    findings = []
    cmd = [
        "semgrep", "scan",
        "--config", "auto",
        "--json",
        "--no-git-ignore",
        "--quiet",
        str(workspace_path),
    ]

    logger.info(f"Running Semgrep: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        # Semgrep returns exit code 1 when findings are present
        if result.returncode not in (0, 1):
            logger.warning(f"Semgrep exited with code {result.returncode}: {result.stderr[:500]}")

        output = json.loads(result.stdout) if result.stdout.strip() else {}
        results = output.get("results", [])

        for r in results:
            rule_id = r.get("check_id", "unknown")
            severity_raw = r.get("extra", {}).get("severity", "INFO")
            path = r.get("path", "")
            line = r.get("start", {}).get("line", 0)
            message = r.get("extra", {}).get("message", rule_id)
            snippet = r.get("extra", {}).get("lines", "")[:500]

            classification = classify_traditional(rule_id, severity_raw)

            findings.append({
                **classification,
                "source": "Unknown",
                "short_title": f"Semgrep: {rule_id}",
                "description": message,
                "impact": f"Potential {classification['risk_type'].lower()} vulnerability detected by static analysis.",
                "location": f"{path}:{line}",
                "evidence_snippet": snippet,
            })

    except subprocess.TimeoutExpired:
        logger.error("Semgrep timed out after 300s")
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"Semgrep error: {e}")

    logger.info(f"Semgrep produced {len(findings)} findings")
    return findings
