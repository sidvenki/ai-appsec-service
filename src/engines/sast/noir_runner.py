"""
OWASP Noir runner – invokes Noir for attack surface discovery (endpoint detection).

Noir analyses source code to discover:
  - API endpoints (REST, GraphQL, WebSocket)
  - Shadow/hidden APIs not in documentation
  - Parameters, headers, and cookies
  - Undocumented routes and admin endpoints behind auth
  - Security issues via rule-based passive scanning

Integration approach:
  1. Run `noir -b <repo_path> -f json -o <output>` to discover endpoints
  2. Parse JSON output for endpoints and parameters
  3. Flag security-relevant findings (shadow APIs, undocumented admin routes, etc.)
  4. Generate OpenAPI spec for enhanced DAST coverage

Requires: noir (Crystal binary) – install via brew, snap, or Docker
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Severity mapping for Noir-discovered issues
NOIR_FINDING_TYPES = {
    "shadow_api": {
        "severity": "P2",
        "control_id": "NR-WEB-01",
        "risk_type": "Shadow/undocumented API endpoint",
    },
    "admin_endpoint": {
        "severity": "P1",
        "control_id": "NR-WEB-02",
        "risk_type": "Administrative endpoint exposed",
    },
    "debug_endpoint": {
        "severity": "P1",
        "control_id": "NR-WEB-03",
        "risk_type": "Debug/development endpoint exposed",
    },
    "unprotected_endpoint": {
        "severity": "P2",
        "control_id": "NR-WEB-04",
        "risk_type": "Potentially unprotected endpoint",
    },
    "sensitive_parameter": {
        "severity": "P2",
        "control_id": "NR-WEB-05",
        "risk_type": "Sensitive parameter in endpoint",
    },
    "file_upload": {
        "severity": "P2",
        "control_id": "NR-WEB-06",
        "risk_type": "File upload endpoint",
    },
    "endpoint_summary": {
        "severity": "P3",
        "control_id": "NR-WEB-99",
        "risk_type": "Attack surface discovery",
    },
}

# Keywords that indicate admin/debug/sensitive endpoints
ADMIN_PATTERNS = [
    "/admin", "/manage", "/internal", "/sys", "/system",
    "/config", "/settings", "/setup", "/install",
    "/superuser", "/root", "/master",
]

DEBUG_PATTERNS = [
    "/debug", "/test", "/dev", "/staging",
    "/health", "/status", "/metrics", "/info",
    "/swagger", "/docs", "/redoc", "/graphql",
    "/playground", "/console", "/__", "/phpinfo",
]

SENSITIVE_PARAMS = [
    "password", "passwd", "secret", "token", "key",
    "api_key", "apikey", "auth", "session", "credential",
    "credit_card", "ssn", "social_security",
]

FILE_UPLOAD_INDICATORS = [
    "upload", "file", "attachment", "image", "document",
    "multipart", "binary",
]


def _classify_endpoint(endpoint: dict) -> list[dict]:
    """Classify an endpoint and generate findings based on security relevance."""
    findings = []
    url = endpoint.get("url", endpoint.get("path", "")).lower()
    method = endpoint.get("method", "GET").upper()
    params = endpoint.get("params", endpoint.get("parameters", []))

    # Check for admin endpoints
    for pattern in ADMIN_PATTERNS:
        if pattern in url:
            findings.append({
                "type": "admin_endpoint",
                "detail": f"{method} {url}",
                "params": params,
            })
            break

    # Check for debug endpoints
    for pattern in DEBUG_PATTERNS:
        if pattern in url:
            findings.append({
                "type": "debug_endpoint",
                "detail": f"{method} {url}",
                "params": params,
            })
            break

    # Check for sensitive parameters
    if isinstance(params, list):
        for param in params:
            param_name = param.get("name", str(param)).lower() if isinstance(param, dict) else str(param).lower()
            for sensitive in SENSITIVE_PARAMS:
                if sensitive in param_name:
                    findings.append({
                        "type": "sensitive_parameter",
                        "detail": f"{method} {url} — parameter: {param_name}",
                        "params": params,
                    })
                    break

    # Check for file upload
    if isinstance(params, list):
        for param in params:
            param_name = param.get("name", str(param)).lower() if isinstance(param, dict) else str(param).lower()
            param_type = param.get("param_type", "").lower() if isinstance(param, dict) else ""
            if any(ind in param_name or ind in param_type for ind in FILE_UPLOAD_INDICATORS):
                findings.append({
                    "type": "file_upload",
                    "detail": f"{method} {url} — file upload parameter: {param_name}",
                    "params": params,
                })
                break

    # Check for DELETE/PUT methods on root-ish paths (potentially destructive)
    if method in ("DELETE", "PUT", "PATCH") and any(seg in url for seg in ["/user", "/account", "/data", "/record"]):
        if not any(f["type"] in ("admin_endpoint", "debug_endpoint") for f in findings):
            findings.append({
                "type": "unprotected_endpoint",
                "detail": f"{method} {url} — destructive method on sensitive resource",
                "params": params,
            })

    return findings


def _parse_noir_json(output_path: str) -> tuple[list[dict], int]:
    """Parse Noir JSON output. Returns (findings, total_endpoint_count)."""
    findings = []
    total_endpoints = 0

    if not os.path.exists(output_path):
        logger.warning(f"Noir output not found at {output_path}")
        return findings, 0

    try:
        with open(output_path, "r") as f:
            data = json.load(f)

        # Noir JSON can be a list of endpoints or an object with endpoints key
        endpoints = data if isinstance(data, list) else data.get("endpoints", data.get("results", []))
        total_endpoints = len(endpoints)

        for ep in endpoints:
            ep_findings = _classify_endpoint(ep)
            findings.extend(ep_findings)

    except (json.JSONDecodeError, IOError, OSError) as e:
        logger.error(f"Could not parse Noir output: {e}")

    return findings, total_endpoints


def run_noir(repo_path: str) -> list[dict]:
    """
    Run OWASP Noir against the repo for attack surface discovery.
    Returns a list of normalised finding dicts.
    """
    if not repo_path or not os.path.isdir(repo_path):
        logger.info("No valid repo path, skipping Noir scan")
        return []

    # Check if noir is installed
    try:
        result = subprocess.run(
            ["noir", "-h"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode not in (0, 1):
            raise FileNotFoundError()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.warning("OWASP Noir not installed. Skipping attack surface discovery. Install via: brew install noir / snap install noir")
        return []

    findings = []
    work_dir = tempfile.mkdtemp(prefix="noir-")

    try:
        json_output = os.path.join(work_dir, "noir_output.json")
        oas_output = os.path.join(work_dir, "noir_openapi.json")

        # Run Noir with JSON output
        cmd = [
            "noir",
            "-b", repo_path,
            "-f", "json",
            "-o", json_output,
            "--no-log",
        ]

        logger.info(f"Running OWASP Noir: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode not in (0, 1):
            logger.warning(f"Noir exited with code {result.returncode}: {result.stderr[:500]}")

        # If JSON output wasn't created, try parsing stdout
        if not os.path.exists(json_output) and result.stdout.strip():
            try:
                with open(json_output, "w") as f:
                    f.write(result.stdout)
            except Exception:
                pass

        # Parse the JSON output
        classified_findings, total_endpoints = _parse_noir_json(json_output)

        # Also generate OAS3 spec for DAST integration
        oas_cmd = [
            "noir",
            "-b", repo_path,
            "-f", "oas3",
            "-o", oas_output,
            "--no-log",
        ]
        try:
            subprocess.run(oas_cmd, capture_output=True, text=True, timeout=120)
            if os.path.exists(oas_output):
                logger.info(f"Noir OpenAPI spec generated at {oas_output}")
        except (subprocess.TimeoutExpired, Exception):
            pass

        # Convert classified findings to normalised format
        for cf in classified_findings:
            finding_type = cf["type"]
            meta = NOIR_FINDING_TYPES.get(finding_type, NOIR_FINDING_TYPES["endpoint_summary"])

            findings.append({
                "severity": meta["severity"],
                "category": "Traditional",
                "risk_type": meta["risk_type"],
                "owasp_llm_id": None,
                "control_id": meta["control_id"],
                "short_title": f"Noir: {meta['risk_type']}",
                "description": (
                    f"OWASP Noir discovered {cf['detail']}. "
                    f"This endpoint was identified through static analysis of the source code "
                    f"and may not be visible through standard crawling."
                ),
                "impact": (
                    f"Exposed {finding_type.replace('_', ' ')} may allow unauthorised access, "
                    f"data exposure, or attack surface expansion."
                ),
                "location": cf["detail"],
                "evidence_snippet": json.dumps(cf.get("params", []), indent=2)[:500] if cf.get("params") else cf["detail"],
            })

        # Add a summary finding with total endpoint count
        if total_endpoints > 0:
            meta = NOIR_FINDING_TYPES["endpoint_summary"]
            sec_findings = len([f for f in classified_findings if f["type"] != "endpoint_summary"])
            findings.append({
                "severity": meta["severity"],
                "category": "Traditional",
                "risk_type": meta["risk_type"],
                "owasp_llm_id": None,
                "control_id": meta["control_id"],
                "short_title": f"Noir: {total_endpoints} endpoints discovered ({sec_findings} security-relevant)",
                "description": (
                    f"OWASP Noir discovered {total_endpoints} API endpoints through "
                    f"static analysis of the source code. Of these, {sec_findings} "
                    f"were flagged as security-relevant (admin, debug, sensitive params, etc.). "
                    f"This endpoint inventory can enhance DAST coverage by testing endpoints "
                    f"that crawlers may miss."
                ),
                "impact": (
                    "Attack surface mapped. Use the generated OpenAPI spec to enhance "
                    "DAST scanning coverage."
                ),
                "location": repo_path,
                "evidence_snippet": f"Total endpoints: {total_endpoints}, Security-relevant: {sec_findings}",
            })

    except subprocess.TimeoutExpired:
        logger.error("Noir timed out after 300s")
    except Exception as e:
        logger.error(f"Noir error: {e}")
    finally:
        # Cleanup
        try:
            import shutil
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass

    logger.info(f"Noir produced {len(findings)} findings")
    return findings
