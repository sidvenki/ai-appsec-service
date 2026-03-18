"""
Bandit runner – invokes Bandit CLI against a workspace and parses JSON output.
"""

import json
import subprocess
import logging
from pathlib import Path
from src.core.severity import classify_traditional

logger = logging.getLogger(__name__)

# Map Bandit severity to our P-levels
BANDIT_SEV_MAP = {
    "HIGH": "P1",
    "MEDIUM": "P2",
    "LOW": "P3",
}


def run_bandit(workspace_path: str) -> list[dict]:
    """
    Run Bandit on all Python files in the workspace.
    Returns a list of normalised finding dicts.
    """
    findings = []
    cmd = [
        "bandit",
        "-r", str(workspace_path),
        "-f", "json",
        "-q",
    ]

    logger.info(f"Running Bandit: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        # Bandit returns exit code 1 when findings are present
        output = json.loads(result.stdout) if result.stdout.strip() else {}
        results = output.get("results", [])

        for r in results:
            test_id = r.get("test_id", "unknown")
            test_name = r.get("test_name", "unknown")
            severity = r.get("issue_severity", "LOW")
            confidence = r.get("issue_confidence", "LOW")
            filename = r.get("filename", "")
            line = r.get("line_number", 0)
            text = r.get("issue_text", "")
            snippet = r.get("code", "")[:500]

            classification = classify_traditional(test_name, severity)
            # Override severity with Bandit's own rating
            classification["severity"] = BANDIT_SEV_MAP.get(severity.upper(), "P3")

            findings.append({
                **classification,
                "source": "Unknown",
                "short_title": f"Bandit {test_id}: {test_name}",
                "description": text,
                "impact": f"{classification['risk_type']} (Confidence: {confidence})",
                "location": f"{filename}:{line}",
                "evidence_snippet": snippet,
            })

    except subprocess.TimeoutExpired:
        logger.error("Bandit timed out after 300s")
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"Bandit error: {e}")

    logger.info(f"Bandit produced {len(findings)} findings")
    return findings
