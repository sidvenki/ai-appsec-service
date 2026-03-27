"""
Agentic Radar runner – invokes SPLX Agentic Radar to analyse agentic AI workflows.

Agentic Radar scans source code to:
  - Discover agent workflows (LangGraph, CrewAI, n8n, OpenAI Agents, AutoGen, Semantic Kernel)
  - Identify tools and external dependencies
  - Detect MCP servers
  - Map vulnerabilities to OWASP LLM Top 10
  - Analyse system prompts for hardening opportunities

Integration approach:
  1. Detect which agentic framework(s) are used in the codebase
  2. Run `agentic-radar scan <framework> -i <repo_path> -o report.html`
  3. Parse the generated HTML report for vulnerability findings
  4. Normalise findings into our standard format

Requires: pip install agentic-radar
"""

import json
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Framework detection patterns
FRAMEWORK_PATTERNS = {
    "langgraph": [
        r"from\s+langgraph",
        r"import\s+langgraph",
        r"StateGraph",
        r"add_edge",
        r"add_node",
    ],
    "crewai": [
        r"from\s+crewai",
        r"import\s+crewai",
        r"CrewAI",
        r"Agent\(",
        r"Task\(",
        r"Crew\(",
    ],
    "openai-agents": [
        r"from\s+openai.*agents",
        r"from\s+agents\s+import",
        r"openai\.agents",
        r"Runner\.run",
        r"Agent\(.*instructions",
    ],
    "n8n": [
        # n8n uses JSON workflows, detected by file extension
    ],
    "autogen": [
        r"from\s+autogen",
        r"import\s+autogen",
        r"autogen_agentchat",
        r"AssistantAgent",
        r"GroupChat",
        r"RoundRobinGroupChat",
    ],
}

# OWASP LLM mapping for Agentic Radar findings
AGENTIC_FINDING_MAP = {
    "tool_vulnerability": {
        "severity": "P1",
        "control_id": "AR-LLM-06",
        "owasp_llm_id": "LLM06",
        "risk_type": "Insecure agent tool",
    },
    "prompt_vulnerability": {
        "severity": "P2",
        "control_id": "AR-LLM-07",
        "owasp_llm_id": "LLM07",
        "risk_type": "System prompt weakness",
    },
    "mcp_server": {
        "severity": "P2",
        "control_id": "AR-LLM-06",
        "owasp_llm_id": "LLM06",
        "risk_type": "MCP server dependency",
    },
    "excessive_permissions": {
        "severity": "P1",
        "control_id": "AR-LLM-06",
        "owasp_llm_id": "LLM06",
        "risk_type": "Excessive agent permissions",
    },
    "missing_guardrails": {
        "severity": "P2",
        "control_id": "AR-LLM-01",
        "owasp_llm_id": "LLM01",
        "risk_type": "Missing prompt guardrails",
    },
    "default": {
        "severity": "P2",
        "control_id": "AR-LLM-99",
        "owasp_llm_id": "LLM06",
        "risk_type": "Agentic workflow vulnerability",
    },
}


def _detect_frameworks(repo_path: str) -> list[str]:
    """Detect which agentic AI frameworks are used in the codebase."""
    detected = []

    # Check for n8n JSON workflows
    for root, dirs, files in os.walk(repo_path):
        for f in files:
            if f.endswith(".json"):
                try:
                    with open(os.path.join(root, f), "r") as fh:
                        content = fh.read(5000)
                        if '"nodes"' in content and '"connections"' in content and '"type"' in content:
                            if "n8n" not in detected:
                                detected.append("n8n")
                except (IOError, UnicodeDecodeError):
                    pass

    # Scan Python files for framework imports
    py_content = []
    for root, dirs, files in os.walk(repo_path):
        # Skip hidden dirs and common non-source dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', '__pycache__', 'venv', '.venv')]
        for f in files:
            if f.endswith(".py"):
                try:
                    with open(os.path.join(root, f), "r") as fh:
                        py_content.append(fh.read(10000))
                except (IOError, UnicodeDecodeError):
                    pass

    all_py = "\n".join(py_content)

    for framework, patterns in FRAMEWORK_PATTERNS.items():
        if framework == "n8n":
            continue
        for pattern in patterns:
            if re.search(pattern, all_py):
                if framework not in detected:
                    detected.append(framework)
                break

    return detected


def _parse_html_report(report_path: str, repo_path: str) -> list[dict]:
    """Parse Agentic Radar HTML report for vulnerability data."""
    findings_data = []

    if not os.path.exists(report_path):
        logger.warning(f"Agentic Radar report not found at {report_path}")
        return []

    try:
        with open(report_path, "r") as f:
            html_content = f.read()

        # Extract vulnerability entries from the HTML report
        # Agentic Radar embeds vulnerability data in the HTML

        # Look for tool vulnerabilities
        tool_sections = re.findall(
            r'(?:vulnerability|vuln|risk|issue|warning).*?(?:tool|function|action).*?(?:<[^>]+>)([^<]+)',
            html_content,
            re.IGNORECASE | re.DOTALL,
        )
        for tool_info in tool_sections:
            tool_name = tool_info.strip()[:200]
            if len(tool_name) > 3:
                findings_data.append({
                    "type": "tool_vulnerability",
                    "detail": tool_name,
                })

        # Look for agent/node names with vulnerabilities
        agent_vulns = re.findall(
            r'(?:agent|node)\s*[:\-]\s*([^<\n]+?)(?:\s*[-–]\s*|\s+)(?:vuln|risk|issue|warning)',
            html_content,
            re.IGNORECASE,
        )
        for agent_info in agent_vulns:
            findings_data.append({
                "type": "excessive_permissions",
                "detail": agent_info.strip()[:200],
            })

        # Look for prompt-related findings
        prompt_findings = re.findall(
            r'(?:prompt|system\s+message|instruction).*?(?:weak|vuln|missing|unhardened|injectable)',
            html_content,
            re.IGNORECASE,
        )
        for pf in prompt_findings:
            findings_data.append({
                "type": "prompt_vulnerability",
                "detail": pf.strip()[:200],
            })

        # Look for MCP server references
        mcp_refs = re.findall(
            r'(?:mcp|model\s+context\s+protocol)\s*(?:server)?[:\s]+([^<\n]+)',
            html_content,
            re.IGNORECASE,
        )
        for mcp in mcp_refs:
            findings_data.append({
                "type": "mcp_server",
                "detail": mcp.strip()[:200],
            })

        # If the report exists but we couldn't parse structured data,
        # look for summary counts / generic vulnerability indicators
        if not findings_data:
            vuln_count_match = re.search(r'(\d+)\s*(?:vulnerabilit|issue|finding|risk)', html_content, re.IGNORECASE)
            if vuln_count_match:
                count = int(vuln_count_match.group(1))
                if count > 0:
                    findings_data.append({
                        "type": "default",
                        "detail": f"Agentic Radar detected {count} potential issues in the agentic workflow",
                    })

            # Check for any tool listings (tools are potential attack surface)
            tool_entries = re.findall(r'(?:tool|function).*?name["\s:]+([^"<\n,]+)', html_content, re.IGNORECASE)
            unique_tools = list(set(t.strip() for t in tool_entries if len(t.strip()) > 2))[:10]
            if unique_tools:
                findings_data.append({
                    "type": "tool_vulnerability",
                    "detail": f"External tools detected in agent workflow: {', '.join(unique_tools)}. Review for excessive permissions.",
                })

    except (IOError, OSError) as e:
        logger.error(f"Could not read Agentic Radar report: {e}")

    return findings_data


def run_agentic_radar(repo_path: str) -> list[dict]:
    """
    Run Agentic Radar against the repo to analyse agentic AI workflows.
    Returns a list of normalised finding dicts.
    """
    if not repo_path or not os.path.isdir(repo_path):
        logger.info("No valid repo path, skipping Agentic Radar scan")
        return []

    # Check if agentic-radar is installed
    try:
        result = subprocess.run(
            ["agentic-radar", "--version"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            raise FileNotFoundError()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.warning("Agentic Radar not installed. Skipping AI-SAST Agentic Radar scan. Install with: pip install agentic-radar")
        return []

    # Detect frameworks
    frameworks = _detect_frameworks(repo_path)
    if not frameworks:
        logger.info("No agentic AI frameworks detected in codebase. Skipping Agentic Radar scan.")
        return []

    logger.info(f"Detected agentic frameworks: {frameworks}")

    findings = []
    work_dir = tempfile.mkdtemp(prefix="agentic-radar-")

    for framework in frameworks:
        report_path = os.path.join(work_dir, f"report_{framework}.html")

        cmd = [
            "agentic-radar", "scan", framework,
            "-i", repo_path,
            "-o", report_path,
        ]

        logger.info(f"Running Agentic Radar ({framework}): {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=repo_path,
            )

            if result.returncode != 0:
                logger.warning(
                    f"Agentic Radar ({framework}) exited with code {result.returncode}: "
                    f"{result.stderr[:500]}"
                )
                # Even on non-zero exit, check if report was generated
                if not os.path.exists(report_path):
                    continue

            # Parse the HTML report
            report_findings = _parse_html_report(report_path, repo_path)

            for rf in report_findings:
                finding_type = rf.get("type", "default")
                meta = AGENTIC_FINDING_MAP.get(finding_type, AGENTIC_FINDING_MAP["default"])

                findings.append({
                    "severity": meta["severity"],
                    "category": "AI/LLM",
                    "risk_type": meta["risk_type"],
                    "owasp_llm_id": meta["owasp_llm_id"],
                    "control_id": meta["control_id"],
                    "short_title": f"Agentic Radar ({framework}): {meta['risk_type']}",
                    "description": (
                        f"Agentic Radar detected a potential vulnerability in the {framework} "
                        f"agentic workflow. {rf.get('detail', '')}"
                    ),
                    "impact": (
                        f"The {framework} agent workflow may be vulnerable to "
                        f"{meta['risk_type'].lower()}. Review agent permissions, tool access, "
                        f"and prompt hardening."
                    ),
                    "location": repo_path,
                    "evidence_snippet": rf.get("detail", "")[:500],
                })

        except subprocess.TimeoutExpired:
            logger.error(f"Agentic Radar ({framework}) timed out after 300s")
        except Exception as e:
            logger.error(f"Agentic Radar ({framework}) error: {e}")

    # Cleanup
    try:
        import shutil
        shutil.rmtree(work_dir, ignore_errors=True)
    except Exception:
        pass

    logger.info(f"Agentic Radar produced {len(findings)} findings across {len(frameworks)} framework(s)")
    return findings
