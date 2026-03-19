# AI AppSec Service – Alpha

Internal security scanning service for Mastek's cyber team. Runs combined traditional SAST/DAST and AI-specific SAST/DAST against applications, with a focus on agentic AI / LLM security.

## Overview

Product and dev teams submit a scan request (repo URL, branch, environment URL, AI usage details). The service:

1. Clones the specified branch into a short-lived workspace
2. Runs **Traditional SAST** (Semgrep + Bandit) on the code
3. Runs **AI-SAST** rule checks for LLM-specific patterns
4. Runs **Traditional DAST** (OWASP ZAP) against the target URL
5. Runs **AI-DAST** probes (prompt injection, RAG poisoning, agent abuse, etc.)
6. Normalises all findings into a unified P1/P2/P3 severity model with OWASP LLM Top 10 mappings
7. Cleans up the workspace (no code stored long-term)

## Quick Start

### Prerequisites

- Python 3.11+
- Git

### Optional (for full coverage)

- **Semgrep**: `pip install semgrep` or `brew install semgrep`
- **Bandit**: `pip install bandit`
- **OWASP ZAP**: [Download](https://www.zaproxy.org/download/) or use Docker

### Install & Run

```bash
# Clone this repo
cd ai-appsec-service

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the service
python main.py
```

The service starts at **http://localhost:8000**.

### Install scanning tools

```bash
# Semgrep (traditional + custom AI SAST rules)
pip install semgrep

# Bandit (Python-specific security checks)
pip install bandit

# OWASP ZAP (optional for alpha – traditional DAST)
# Docker: docker pull zaproxy/zap-stable
# Or install from https://www.zaproxy.org/download/
```

## UI Pages

| Page | URL | Description |
|------|-----|-------------|
| Home | `/` | Landing page with links |
| New Scan | `/new-scan` | Scan request intake form |
| Dashboard | `/dashboard` | List of all scan requests + status |
| Results | `/results/{id}` | Findings view with summary, table, detail panel |

## API Endpoints

### Create Scan Request

```
POST /api/scan-requests
Content-Type: application/json
```

**Request body:**

```json
{
  "requester_name": "Siddharth Venkataraman",
  "team": "Cyber Security",
  "email": "siddharth.venkataraman@mastek.com",
  "app_name": "Customer Support AI Agent",
  "description": "FastAPI app with GPT-4 chat, RAG pipeline, and agent tools",
  "repo_url": "https://github.com/example/ai-support-agent.git",
  "branch": "main",
  "env_base_url": "http://localhost:9000",
  "llm_usage": "Uses OpenAI GPT-4 for customer query handling. Agent can search DB and send emails.",
  "data_profile": "Handles PII (names, emails). Accesses internal knowledge base."
}
```

**Response:**

```json
{
  "scan_request_id": 1,
  "status": "scan_triggered"
}
```

### Get Scan Request Status

```
GET /api/scan-requests/{id}
```

**Response:**

```json
{
  "scan_request": { ... },
  "latest_run": {
    "id": 1,
    "status": "completed",
    "started_at": "2026-03-18 12:00:00",
    "finished_at": "2026-03-18 12:02:30"
  },
  "finding_summary": {
    "total": 15,
    "p1": 4,
    "p2": 6,
    "p3": 5,
    "traditional": 8,
    "ai_llm": 7
  }
}
```

### Get Findings

```
GET /api/scan-runs/{run_id}/findings
```

**Response:**

```json
{
  "scan_run_id": 1,
  "status": "completed",
  "total_findings": 15,
  "findings": [
    {
      "id": 1,
      "severity": "P1",
      "category": "AI/LLM",
      "risk_type": "Prompt injection sink",
      "owasp_llm_id": "LLM01",
      "control_id": "PR-LLM-01",
      "short_title": "User input interpolated into LLM prompt",
      "description": "User-controlled input is directly interpolated...",
      "impact": "An attacker can manipulate the LLM's behaviour...",
      "location": "vulnerable_ai_app.py:72",
      "evidence_snippet": "system_prompt = f\"You are a helpful assistant..."
    }
  ]
}
```

## Severity Model

| Level | Meaning | Examples |
|-------|---------|---------|
| **P1** | System-level compromise / severe safety or data impact | SQL injection, prompt injection with data exfil, model output in exec() |
| **P2** | Strong security or trust degradation | XSS, secrets in prompts, RAG poisoning, unbounded LLM loops |
| **P3** | Real weakness with limited impact | Weak crypto, misinformation, open redirect |

## Finding Data Model

Each finding includes:

| Field | Description |
|-------|-------------|
| `severity` | P1, P2, or P3 |
| `category` | "Traditional" or "AI/LLM" |
| `risk_type` | e.g. "SQL injection", "Prompt injection" |
| `owasp_llm_id` | LLM01, LLM06, etc. (null for traditional) |
| `control_id` | e.g. PR-LLM-03, TRAD-WEB-01 |
| `short_title` | One-line finding title |
| `description` | Detailed description |
| `impact` | Impact statement |
| `location` | File:line or URL |
| `evidence_snippet` | Short code/response excerpt |

## AI-SAST Rules (v1)

| # | Pattern | OWASP LLM | Control |
|---|---------|-----------|---------|
| 1 | Untrusted input in system/developer prompts | LLM01 | PR-LLM-01 |
| 2 | Direct string interpolation of user input into prompts | LLM01 | PR-LLM-01 |
| 3 | Model output used in exec/eval/subprocess/SQL | LLM02 | PR-LLM-02 |
| 4 | Model output rendered as HTML without escaping | LLM02 | PR-LLM-03 |
| 5 | Insecure agent tool invocation (no validation) | LLM06 | PR-LLM-06 |
| 6 | Secrets/keys in prompts or LLM context | LLM02 | PR-LLM-04 |
| 7 | Unbounded loops/retries around LLM calls | LLM10 | PR-LLM-10 |

## AI-DAST Probes (v1)

| # | Probe Family | OWASP LLM | Control |
|---|-------------|-----------|---------|
| 1 | Prompt injection & jailbreak | LLM01 | PR-LLM-01 |
| 2 | RAG poisoning simulation | LLM03/LLM02 | PR-RAG-01 |
| 3 | Agent/tool abuse prompts | LLM06 | PR-LLM-06 |
| 4 | Unbounded consumption tests | LLM10 | PR-LLM-10 |
| 5 | Misinformation / hallucination tests | LLM09 | PR-LLM-09 |

## Testing with Sample Vulnerable App

A deliberately vulnerable app is included in `sample_app/` for testing:

```bash
# In a separate terminal, start the vulnerable app:
cd sample_app
pip install -r requirements.txt
uvicorn vulnerable_ai_app:app --host 0.0.0.0 --port 9000
```

Then submit a scan request via the UI or API pointing to the sample app's repo and `http://localhost:9000` as the environment URL.

## Project Structure

```
ai-appsec-service/
├── main.py                          # FastAPI entry point
├── requirements.txt                 # Python dependencies
├── README.md
├── src/
│   ├── api/
│   │   └── routes.py                # API endpoints
│   ├── core/
│   │   ├── orchestrator.py          # Scan workflow engine
│   │   └── severity.py              # Severity + control mapping
│   ├── engines/
│   │   ├── sast/
│   │   │   ├── semgrep_runner.py    # Semgrep CLI wrapper
│   │   │   └── bandit_runner.py     # Bandit CLI wrapper
│   │   ├── dast/
│   │   │   └── zap_runner.py        # OWASP ZAP wrapper
│   │   ├── ai_sast/
│   │   │   └── rules.py             # AI-specific SAST checks
│   │   └── ai_dast/
│   │       └── probes.py            # AI-specific DAST probes
│   ├── models/
│   │   └── database.py              # SQLAlchemy models + SQLite
│   └── utils/
├── templates/                       # Jinja2 HTML templates
│   ├── base.html
│   ├── index.html
│   ├── new_scan.html
│   ├── results.html
│   └── dashboard.html
├── static/
│   └── css/style.css                # UI stylesheet
├── configs/
│   └── semgrep/ai-rules.yaml        # Custom Semgrep rules for AI
├── sample_app/                      # Test target (deliberately vulnerable)
│   ├── vulnerable_ai_app.py
│   └── requirements.txt
├── tests/
└── scripts/
```

## Architecture

```
[Dev Team] → [UI + API] → [ScanRequest in SQLite]
                                ↓
                    [Scan Orchestrator]
                         ↓
               [Temp Workspace (/tmp)]
                    ↓         ↓
         SAST (Semgrep/    DAST (ZAP +
         Bandit + AI)      AI probes)
                    ↓         ↓
              [Findings normalised in DB]
                         ↓
                [Results UI + Detail Panel]
                         ↓
                  [Cyber Team reviews]
```

## Roadmap (Post-Alpha)

- [ ] AI Assistant for remediation guidance
- [ ] Threat modelling module
- [ ] Red teaming automation
- [ ] Computer-generated code tagging (CM-CTRL controls)
- [ ] Task queue (Celery/RQ) for production workloads
- [ ] Docker containerisation
- [ ] PDF/HTML report export
- [ ] Commercial tool adapters (HCL AppScan, Equixly, Rapid7)

## License

Internal use only – Mastek Cyber Security Team.
