"""
Garak runner – invokes NVIDIA Garak LLM vulnerability scanner against a target endpoint.

Garak is a comprehensive LLM security scanner with 150+ probe types and 3,000+ prompt templates.
It connects to REST endpoints via a configurable JSON template and outputs results as JSONL.

Integration approach:
  1. Generate a REST config JSON for the target LLM endpoint
  2. Run garak with selected probe categories via CLI
  3. Parse JSONL report output
  4. Normalise findings into our standard format

Requires: pip install garak
"""

import json
import logging
import os
import subprocess
import tempfile
import glob as glob_module
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Garak probe categories mapped to OWASP LLM Top 10 ─────────────────────
# We select high-value probes rather than running ALL (which can take hours)
GARAK_PROBE_SETS = {
    "prompt_injection": {
        "probes": "promptinject",
        "owasp_llm_id": "LLM01",
        "risk_type": "Prompt injection",
        "control_id": "GK-LLM-01",
        "severity": "P1",
    },
    "dan_jailbreak": {
        "probes": "dan",
        "owasp_llm_id": "LLM01",
        "risk_type": "Jailbreak (DAN)",
        "control_id": "GK-LLM-01",
        "severity": "P1",
    },
    "encoding_attacks": {
        "probes": "encoding",
        "owasp_llm_id": "LLM01",
        "risk_type": "Encoded prompt injection",
        "control_id": "GK-LLM-01",
        "severity": "P1",
    },
    "hallucination": {
        "probes": "snowball",
        "owasp_llm_id": "LLM09",
        "risk_type": "Hallucination / confabulation",
        "control_id": "GK-LLM-09",
        "severity": "P2",
    },
    "data_leakage": {
        "probes": "leakreplay",
        "owasp_llm_id": "LLM02",
        "risk_type": "Training data leakage",
        "control_id": "GK-LLM-02",
        "severity": "P1",
    },
    "malware_generation": {
        "probes": "malwaregen",
        "owasp_llm_id": "LLM02",
        "risk_type": "Malware code generation",
        "control_id": "GK-LLM-02",
        "severity": "P1",
    },
    "package_hallucination": {
        "probes": "packagehallucination",
        "owasp_llm_id": "LLM05",
        "risk_type": "Package hallucination (supply chain)",
        "control_id": "GK-LLM-05",
        "severity": "P2",
    },
    "known_bad_signatures": {
        "probes": "knownbadsignatures",
        "owasp_llm_id": "LLM01",
        "risk_type": "Known bad signature bypass",
        "control_id": "GK-LLM-01",
        "severity": "P1",
    },
}

# Probes to run by default (balanced speed vs coverage – ~15-20 min)
DEFAULT_PROBE_KEYS = [
    "prompt_injection",
    "dan_jailbreak",
    "encoding_attacks",
    "hallucination",
    "package_hallucination",
    "known_bad_signatures",
]


def _build_rest_config(target_url: str, config_path: str) -> None:
    """Generate a Garak REST generator config JSON for the target LLM endpoint."""
    # Try common chat endpoint patterns
    config = {
        "rest": {
            "RestGenerator": {
                "name": "target_llm",
                "uri": target_url.rstrip("/") + "/api/chat",
                "method": "post",
                "headers": {
                    "Content-Type": "application/json",
                },
                "req_template_json_object": {
                    "message": "$INPUT"
                },
                "response_json": True,
                "response_json_field": "$.response",
                "request_timeout": 60,
            }
        }
    }
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    logger.info(f"Garak REST config written to {config_path}")


def _parse_garak_report(report_dir: str) -> list[dict]:
    """Parse Garak JSONL report files and extract failed probes."""
    results = []

    # Garak writes report files as JSONL in ~/.local/share/garak/garak_runs/ or the --report_prefix dir
    jsonl_files = glob_module.glob(os.path.join(report_dir, "**/*.jsonl"), recursive=True)
    if not jsonl_files:
        # Also check default garak location
        home_garak = os.path.expanduser("~/.local/share/garak/garak_runs/")
        jsonl_files = sorted(glob_module.glob(os.path.join(home_garak, "**/*.jsonl"), recursive=True))
        if jsonl_files:
            # Take only the most recent report
            jsonl_files = [jsonl_files[-1]]

    for jsonl_file in jsonl_files:
        try:
            with open(jsonl_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        # Garak JSONL entries have 'status' field: 1 = fail (vulnerability found)
                        if entry.get("status") == 1 or entry.get("passed") is False:
                            results.append(entry)
                    except json.JSONDecodeError:
                        continue
        except (IOError, OSError) as e:
            logger.warning(f"Could not read Garak report {jsonl_file}: {e}")

    return results


def run_garak(target_url: str, probe_keys: list[str] = None) -> list[dict]:
    """
    Run Garak LLM vulnerability scanner against the target URL.
    Returns a list of normalised finding dicts.
    """
    if not target_url:
        logger.info("No target URL provided, skipping Garak scan")
        return []

    # Check if garak is installed
    try:
        subprocess.run(["python3", "-m", "garak", "--version"], capture_output=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.warning("Garak not installed. Skipping AI-DAST Garak scan. Install with: pip install garak")
        return []

    if probe_keys is None:
        probe_keys = DEFAULT_PROBE_KEYS

    findings = []
    work_dir = tempfile.mkdtemp(prefix="garak-")

    try:
        # Build REST config
        config_path = os.path.join(work_dir, "rest_config.json")
        _build_rest_config(target_url, config_path)

        # Build probe list
        probes_to_run = []
        probe_metadata = {}
        for key in probe_keys:
            if key in GARAK_PROBE_SETS:
                probe_info = GARAK_PROBE_SETS[key]
                probes_to_run.append(probe_info["probes"])
                probe_metadata[probe_info["probes"]] = probe_info

        if not probes_to_run:
            logger.warning("No valid Garak probe sets selected")
            return []

        probe_csv = ",".join(probes_to_run)
        report_prefix = os.path.join(work_dir, "garak_report")

        cmd = [
            "python3", "-m", "garak",
            "--model_type", "rest",
            "-G", config_path,
            "--probes", probe_csv,
            "--report_prefix", report_prefix,
            "--generations", "3",
            "--parallel_attempts", "2",
        ]

        logger.info(f"Running Garak: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,  # 30 min max
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )

        if result.returncode not in (0, 1):
            logger.warning(f"Garak exited with code {result.returncode}: {result.stderr[:500]}")

        # Parse results
        failed_probes = _parse_garak_report(work_dir)

        for entry in failed_probes:
            probe_name = entry.get("probe", entry.get("probe_classname", "unknown"))
            prompt = entry.get("prompt", "")[:500]
            response = entry.get("output", entry.get("outputs", [""]))[0] if isinstance(entry.get("output", entry.get("outputs", "")), list) else str(entry.get("output", ""))[:500]
            detector = entry.get("detector", "")

            # Match to our probe metadata
            matched_meta = None
            probe_lower = probe_name.lower()
            for probe_key, meta in probe_metadata.items():
                if probe_key.lower() in probe_lower:
                    matched_meta = meta
                    break

            if not matched_meta:
                matched_meta = {
                    "severity": "P2",
                    "control_id": "GK-LLM-99",
                    "owasp_llm_id": "LLM01",
                    "risk_type": "LLM vulnerability (Garak)",
                }

            findings.append({
                "severity": matched_meta["severity"],
                "category": "AI/LLM",
                "risk_type": matched_meta["risk_type"],
                "owasp_llm_id": matched_meta["owasp_llm_id"],
                "control_id": matched_meta["control_id"],
                "short_title": f"Garak: {probe_name}",
                "description": (
                    f"Garak probe '{probe_name}' detected a vulnerability. "
                    f"Detector: {detector}. The LLM responded in a way indicating "
                    f"the attack was successful."
                ),
                "impact": f"LLM is vulnerable to {matched_meta['risk_type'].lower()}. "
                          f"This could allow attackers to exploit the model.",
                "location": target_url,
                "evidence_snippet": f"Prompt: {prompt[:250]}\n\nResponse: {response[:250]}",
            })

    except subprocess.TimeoutExpired:
        logger.error("Garak timed out after 1800s")
    except Exception as e:
        logger.error(f"Garak error: {e}")
    finally:
        # Cleanup
        try:
            import shutil
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass

    logger.info(f"Garak produced {len(findings)} findings")
    return findings
