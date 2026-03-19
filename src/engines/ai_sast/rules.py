"""
AI-specific SAST rule checks.

Implements AST/regex-based analysers for these patterns:
  1. Untrusted input in system/developer prompts (LLM01)
  2. Direct string interpolation of user input into prompts (LLM01)
  3. Model output used in exec/eval/subprocess/SQL (LLM02)
  4. Model output rendered as HTML without escaping (LLM02)
  5. Insecure agent tool invocation: model-controlled args, no validation (LLM06)
  6. Secrets/keys in prompts or LLM context (LLM02)
  7. Unbounded loops/retries around LLM calls (LLM10)
"""

import ast
import re
import logging
from pathlib import Path
from src.core.severity import classify_ai_sast

logger = logging.getLogger(__name__)

# ── Patterns ──────────────────────────────────────────────────────────────

# Known LLM API call patterns
LLM_CALL_PATTERNS = [
    r"openai\.\w+\.create",
    r"client\.chat\.completions\.create",
    r"client\.completions\.create",
    r"anthropic\.\w+\.messages\.create",
    r"litellm\.completion",
    r"langchain.*\.invoke",
    r"langchain.*\.run",
    r"\.generate\(",
    r"\.predict\(",
]

# Dangerous exec patterns
EXEC_PATTERNS = [
    "exec(", "eval(", "subprocess.run(", "subprocess.call(",
    "subprocess.Popen(", "os.system(", "os.popen(",
    "cursor.execute(", ".execute(",
]

# Secret patterns in string literals
SECRET_PATTERNS = [
    r"sk-[a-zA-Z0-9]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[a-zA-Z0-9]{36}",
    r"api[_-]?key\s*[:=]\s*['\"][^'\"]{10,}",
    r"password\s*[:=]\s*['\"][^'\"]{4,}",
    r"secret\s*[:=]\s*['\"][^'\"]{8,}",
    r"bearer\s+[a-zA-Z0-9\-._~+/]+=*",
]

# HTML rendering without escaping
HTML_RENDER_PATTERNS = [
    r"Markup\(",
    r"\|safe",
    r"innerHTML\s*=",
    r"dangerouslySetInnerHTML",
    r"Response\(.*(content_type|media_type).*html",
    r"HTMLResponse\(",
]

# Agent / tool invocation patterns
AGENT_TOOL_PATTERNS = [
    r"tool_call\(",
    r"function_call\(",
    r"\.run_tool\(",
    r"\.execute_tool\(",
    r"agent.*\.run\(",
    r"ToolExecutor",
    r"tool_choice",
]


def scan_file(filepath: Path) -> list[dict]:
    """Scan a single Python file for AI-specific security issues."""
    findings = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        lines = content.split("\n")
    except Exception as e:
        logger.debug(f"Cannot read {filepath}: {e}")
        return findings

    # ── Check 1 & 2: Prompt injection sinks ────────────────────────────
    # Look for f-strings or .format() that include user/request variables
    # inside LLM API calls
    _check_prompt_injection(filepath, content, lines, findings)

    # ── Check 3: Model output in exec/eval/subprocess/SQL ──────────────
    _check_model_output_exec(filepath, content, lines, findings)

    # ── Check 4: Model output rendered as unescaped HTML ───────────────
    _check_model_output_html(filepath, content, lines, findings)

    # ── Check 5: Insecure agent tool invocation ────────────────────────
    _check_insecure_agent_tool(filepath, content, lines, findings)

    # ── Check 6: Secrets in prompts / LLM context ──────────────────────
    _check_secrets_in_prompt(filepath, content, lines, findings)

    # ── Check 7: Unbounded loops around LLM calls ─────────────────────
    _check_unbounded_loops(filepath, content, lines, findings)

    return findings


def _check_prompt_injection(filepath, content, lines, findings):
    """Detect user input interpolated into LLM prompts."""
    # Pattern: f"...{user_input}..." or "...".format(user_input) near LLM calls
    user_var_patterns = [
        r"request\.\w+", r"user_input", r"user_message", r"query",
        r"body\[", r"data\[", r"params\[", r"form\[",
        r"input_text", r"prompt_text", r"user_prompt",
    ]

    for i, line in enumerate(lines, 1):
        # Check for f-strings or format() with user vars
        is_fstring = "f'" in line or 'f"' in line
        is_format = ".format(" in line
        has_concat = "+" in line and ("prompt" in line.lower() or "system" in line.lower())

        if is_fstring or is_format or has_concat:
            for uvp in user_var_patterns:
                if re.search(uvp, line, re.IGNORECASE):
                    # Check proximity to LLM calls (within 20 lines)
                    context_start = max(0, i - 10)
                    context_end = min(len(lines), i + 10)
                    context_block = "\n".join(lines[context_start:context_end])

                    has_llm_call = any(
                        re.search(p, context_block) for p in LLM_CALL_PATTERNS
                    )
                    if has_llm_call or "prompt" in line.lower() or "system" in line.lower():
                        cls = classify_ai_sast("prompt_injection_sink")
                        findings.append({
                            **cls,
                                    "short_title": "User input interpolated into LLM prompt",
                            "description": (
                                "User-controlled input is directly interpolated into a prompt string "
                                "via f-string, .format(), or concatenation. This can allow prompt injection."
                            ),
                            "impact": "An attacker can manipulate the LLM's behaviour by injecting instructions.",
                            "location": f"{filepath}:{i}",
                            "evidence_snippet": line.strip()[:300],
                        })
                        break  # one finding per line


def _check_model_output_exec(filepath, content, lines, findings):
    """Detect model output flowing into exec/eval/subprocess/SQL."""
    # Look for patterns where a variable from LLM response feeds into dangerous calls
    output_vars = set()

    for i, line in enumerate(lines, 1):
        # Track variables that receive LLM output
        for pattern in LLM_CALL_PATTERNS:
            if re.search(pattern, line):
                # Try to find the assignment target
                match = re.match(r"\s*(\w+)\s*=", line)
                if match:
                    output_vars.add(match.group(1))
                # Also track common patterns
                for var in ["response", "result", "completion", "output", "answer", "reply"]:
                    if var in line.lower():
                        output_vars.add(var)

        # Check if any tracked output var is used in dangerous calls
        for exec_pat in EXEC_PATTERNS:
            if exec_pat in line:
                for var in output_vars:
                    if var in line:
                        cls = classify_ai_sast("model_output_exec")
                        findings.append({
                            **cls,
                                    "short_title": "Model output used in exec/eval/subprocess/SQL",
                            "description": (
                                f"Variable '{var}' (likely containing LLM output) is passed to "
                                f"a dangerous function ({exec_pat.strip('(')}). "
                                "This can lead to arbitrary code execution."
                            ),
                            "impact": "System-level compromise if attacker controls model output.",
                            "location": f"{filepath}:{i}",
                            "evidence_snippet": line.strip()[:300],
                        })
                        break


def _check_model_output_html(filepath, content, lines, findings):
    """Detect model output rendered as HTML without escaping."""
    for i, line in enumerate(lines, 1):
        for pattern in HTML_RENDER_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Check if there's an LLM-related variable nearby
                context_start = max(0, i - 15)
                context_block = "\n".join(lines[context_start:i])
                llm_related = any(
                    v in context_block.lower()
                    for v in ["response", "completion", "output", "result", "answer",
                              "generated", "llm", "openai", "anthropic", "model"]
                )
                if llm_related:
                    cls = classify_ai_sast("model_output_html")
                    findings.append({
                        **cls,
                            "short_title": "Model output rendered as unescaped HTML",
                        "description": (
                            "LLM output appears to be rendered as raw HTML without escaping. "
                            "This can lead to XSS if the model output contains malicious scripts."
                        ),
                        "impact": "Cross-site scripting via model-generated content.",
                        "location": f"{filepath}:{i}",
                        "evidence_snippet": line.strip()[:300],
                    })


def _check_insecure_agent_tool(filepath, content, lines, findings):
    """Detect insecure agent tool invocation with model-controlled arguments."""
    for i, line in enumerate(lines, 1):
        for pattern in AGENT_TOOL_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Check if the arguments come from model output (no validation visible)
                context_start = max(0, i - 10)
                context_end = min(len(lines), i + 5)
                context_block = "\n".join(lines[context_start:context_end])

                has_validation = any(
                    v in context_block.lower()
                    for v in ["validate", "sanitize", "whitelist", "allowlist",
                              "check_", "verify", "assert", "if ", "schema"]
                )
                has_model_input = any(
                    v in context_block.lower()
                    for v in ["response", "completion", "output", "tool_call",
                              "function_call", "arguments", "model"]
                )

                if has_model_input and not has_validation:
                    cls = classify_ai_sast("insecure_agent_tool")
                    findings.append({
                        **cls,
                            "short_title": "Insecure agent tool invocation",
                        "description": (
                            "An agent tool is invoked with arguments that appear to come from "
                            "model output, with no visible input validation or allowlisting."
                        ),
                        "impact": "Model can invoke tools with arbitrary arguments, enabling data destruction or exfiltration.",
                        "location": f"{filepath}:{i}",
                        "evidence_snippet": line.strip()[:300],
                    })
                    break


def _check_secrets_in_prompt(filepath, content, lines, findings):
    """Detect secrets or API keys embedded in prompt strings or LLM context."""
    for i, line in enumerate(lines, 1):
        # Only flag if line looks like it's part of a prompt / LLM context
        is_prompt_context = any(
            kw in line.lower()
            for kw in ["prompt", "system", "message", "context", "instruction"]
        )
        if not is_prompt_context:
            continue

        for pattern in SECRET_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                cls = classify_ai_sast("secrets_in_prompt")
                findings.append({
                    **cls,
                    "short_title": "Secret or API key found in LLM prompt/context",
                    "description": (
                        "A string that looks like an API key, password, or secret token was found "
                        "in a prompt template or LLM context string. This risks leaking credentials "
                        "via model output or logs."
                    ),
                    "impact": "Credential exposure via model responses or prompt logs.",
                    "location": f"{filepath}:{i}",
                    "evidence_snippet": re.sub(
                        r"[a-zA-Z0-9]{8,}", "***REDACTED***", line.strip()[:300]
                    ),
                })
                break


def _check_unbounded_loops(filepath, content, lines, findings):
    """Detect unbounded loops/retries around LLM calls."""
    for i, line in enumerate(lines, 1):
        # Look for while True or while loops without clear bounds near LLM calls
        is_while_true = re.match(r"\s*while\s+(True|1)\s*:", line)
        is_while_loop = re.match(r"\s*while\s+", line)
        is_for_retry = re.search(r"for\s+\w+\s+in\s+range\s*\(\s*\d{3,}", line)  # range(100+)

        if is_while_true or is_for_retry:
            # Check if there's an LLM call inside the loop body (next 20 lines)
            context_end = min(len(lines), i + 20)
            loop_body = "\n".join(lines[i:context_end])
            has_llm_call = any(
                re.search(p, loop_body) for p in LLM_CALL_PATTERNS
            )
            if has_llm_call:
                cls = classify_ai_sast("unbounded_llm_loop")
                findings.append({
                    **cls,
                    "short_title": "Unbounded loop/retry around LLM call",
                    "description": (
                        "An LLM API call is inside a loop with no clear upper bound. "
                        "This can lead to runaway costs, denial of service, or resource exhaustion."
                    ),
                    "impact": "Potential unbounded API spend and service disruption.",
                    "location": f"{filepath}:{i}",
                    "evidence_snippet": line.strip()[:300],
                })


def run_ai_sast(workspace_path: str) -> list[dict]:
    """
    Run all AI-SAST checks on Python files in the workspace.
    Returns a list of normalised finding dicts.
    """
    all_findings = []
    workspace = Path(workspace_path)

    python_files = list(workspace.rglob("*.py"))
    logger.info(f"AI-SAST scanning {len(python_files)} Python files in {workspace_path}")

    for py_file in python_files:
        # Skip virtualenvs and hidden dirs
        parts = py_file.parts
        if any(p.startswith(".") or p in ("venv", "env", "__pycache__", "node_modules") for p in parts):
            continue
        file_findings = scan_file(py_file)
        all_findings.extend(file_findings)

    logger.info(f"AI-SAST produced {len(all_findings)} findings")
    return all_findings
