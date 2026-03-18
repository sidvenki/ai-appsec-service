"""
Severity model and control mapping for AI AppSec Service.

Unified impact-centric scheme:
  P1: system-level compromise / severe safety or data impact
  P2: strong security or trust degradation
  P3: real weakness with limited impact

Each finding stores: severity, category, risk_type, owasp_llm_id, control_id, source.
"""

# ---------------------------------------------------------------------------
# Traditional SAST/DAST → severity + control_id
# ---------------------------------------------------------------------------

TRADITIONAL_SEVERITY_MAP: dict[str, dict] = {
    # Semgrep / Bandit rule categories → severity + control
    "sql_injection":          {"severity": "P1", "control_id": "TRAD-WEB-01", "risk_type": "SQL injection"},
    "command_injection":      {"severity": "P1", "control_id": "TRAD-WEB-02", "risk_type": "Command injection"},
    "xss":                    {"severity": "P2", "control_id": "TRAD-WEB-03", "risk_type": "Cross-site scripting"},
    "ssrf":                   {"severity": "P1", "control_id": "TRAD-WEB-04", "risk_type": "SSRF"},
    "path_traversal":         {"severity": "P2", "control_id": "TRAD-WEB-05", "risk_type": "Path traversal"},
    "hardcoded_secret":       {"severity": "P2", "control_id": "TRAD-WEB-06", "risk_type": "Hardcoded secret"},
    "insecure_deserialization": {"severity": "P1", "control_id": "TRAD-WEB-07", "risk_type": "Insecure deserialization"},
    "weak_crypto":            {"severity": "P3", "control_id": "TRAD-WEB-08", "risk_type": "Weak cryptography"},
    "insecure_config":        {"severity": "P3", "control_id": "TRAD-WEB-09", "risk_type": "Insecure configuration"},
    "auth_bypass":            {"severity": "P1", "control_id": "TRAD-WEB-10", "risk_type": "Authentication bypass"},
    "open_redirect":          {"severity": "P3", "control_id": "TRAD-WEB-11", "risk_type": "Open redirect"},
    "default":                {"severity": "P3", "control_id": "TRAD-WEB-99", "risk_type": "General security issue"},
}

# ---------------------------------------------------------------------------
# AI/LLM SAST → severity + control_id + OWASP LLM ID
# ---------------------------------------------------------------------------

AI_SAST_SEVERITY_MAP: dict[str, dict] = {
    "prompt_injection_sink": {
        "severity": "P1", "control_id": "PR-LLM-01",
        "owasp_llm_id": "LLM01", "risk_type": "Prompt injection sink",
    },
    "model_output_exec": {
        "severity": "P1", "control_id": "PR-LLM-02",
        "owasp_llm_id": "LLM02", "risk_type": "Model output in exec/eval/subprocess",
    },
    "model_output_html": {
        "severity": "P2", "control_id": "PR-LLM-03",
        "owasp_llm_id": "LLM02", "risk_type": "Model output rendered as unescaped HTML",
    },
    "insecure_agent_tool": {
        "severity": "P1", "control_id": "PR-LLM-06",
        "owasp_llm_id": "LLM06", "risk_type": "Insecure agent tool invocation",
    },
    "secrets_in_prompt": {
        "severity": "P2", "control_id": "PR-LLM-04",
        "owasp_llm_id": "LLM02", "risk_type": "Secrets/keys in prompts or LLM context",
    },
    "unbounded_llm_loop": {
        "severity": "P2", "control_id": "PR-LLM-10",
        "owasp_llm_id": "LLM10", "risk_type": "Unbounded loops/retries around LLM calls",
    },
}

# ---------------------------------------------------------------------------
# AI/LLM DAST → severity + control_id + OWASP LLM ID
# ---------------------------------------------------------------------------

AI_DAST_SEVERITY_MAP: dict[str, dict] = {
    "prompt_injection_success": {
        "severity": "P1", "control_id": "PR-LLM-01",
        "owasp_llm_id": "LLM01", "risk_type": "Prompt injection",
    },
    "jailbreak_success": {
        "severity": "P1", "control_id": "PR-LLM-01",
        "owasp_llm_id": "LLM01", "risk_type": "Jailbreak",
    },
    "rag_poisoning": {
        "severity": "P2", "control_id": "PR-RAG-01",
        "owasp_llm_id": "LLM03", "risk_type": "RAG poisoning",
    },
    "agent_tool_abuse": {
        "severity": "P1", "control_id": "PR-LLM-06",
        "owasp_llm_id": "LLM06", "risk_type": "Excess agency / tool abuse",
    },
    "unbounded_consumption": {
        "severity": "P2", "control_id": "PR-LLM-10",
        "owasp_llm_id": "LLM10", "risk_type": "Unbounded consumption",
    },
    "misinformation": {
        "severity": "P3", "control_id": "PR-LLM-09",
        "owasp_llm_id": "LLM09", "risk_type": "Misinformation / hallucination",
    },
}


def classify_traditional(rule_id: str, semgrep_severity: str | None = None) -> dict:
    """Return severity + control info for a traditional finding."""
    rule_lower = rule_id.lower()
    for key, mapping in TRADITIONAL_SEVERITY_MAP.items():
        if key != "default" and key in rule_lower:
            return {**mapping, "category": "Traditional", "owasp_llm_id": None}
    # Fall back to semgrep severity if available
    if semgrep_severity:
        sev_map = {"ERROR": "P1", "WARNING": "P2", "INFO": "P3"}
        severity = sev_map.get(semgrep_severity.upper(), "P3")
    else:
        severity = "P3"
    default = TRADITIONAL_SEVERITY_MAP["default"].copy()
    default["severity"] = severity
    return {**default, "category": "Traditional", "owasp_llm_id": None}


def classify_ai_sast(check_id: str) -> dict:
    """Return severity + control info for an AI-SAST finding."""
    mapping = AI_SAST_SEVERITY_MAP.get(check_id, {
        "severity": "P3", "control_id": "PR-LLM-99",
        "owasp_llm_id": None, "risk_type": "AI/LLM code pattern",
    })
    return {**mapping, "category": "AI/LLM"}


def classify_ai_dast(probe_id: str) -> dict:
    """Return severity + control info for an AI-DAST finding."""
    mapping = AI_DAST_SEVERITY_MAP.get(probe_id, {
        "severity": "P3", "control_id": "PR-LLM-99",
        "owasp_llm_id": None, "risk_type": "AI/LLM runtime probe",
    })
    return {**mapping, "category": "AI/LLM"}
